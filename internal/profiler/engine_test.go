package profiler

import (
	"io"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// cannedTransport serves fixed bodies by URL, and 404 for anything else.
type cannedTransport map[string]string

func (c cannedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body, ok := c[req.URL.String()]
	status := http.StatusOK
	if !ok {
		status = http.StatusNotFound
	}
	header := http.Header{}
	switch {
	case strings.HasSuffix(req.URL.Path, ".js"):
		header.Set("Content-Type", "application/javascript")
	case strings.HasSuffix(req.URL.Path, ".css"):
		header.Set("Content-Type", "text/css")
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
}

// testEngine returns an engine for apps, with HTTP served from assets and
// DNS disabled for the duration of the test.
func testEngine(t *testing.T, apps map[string]*Fingerprint, assets cannedTransport) *Wappalyze {
	t.Helper()
	oldTransport, oldDNS := http.DefaultTransport, DNSRecordTypes
	http.DefaultTransport = assets
	DNSRecordTypes = nil
	t.Cleanup(func() { http.DefaultTransport, DNSRecordTypes = oldTransport, oldDNS })
	f, dropped := compileFingerprints(apps)
	if len(dropped) > 0 {
		t.Fatalf("dropped patterns: %q", dropped)
	}
	return &Wappalyze{fingerprints: f, regexTimeout: time.Second}
}

func techList(m map[string]struct{}) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func checkTechs(t *testing.T, name string, got map[string]struct{}, want ...string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	sort.Strings(want)
	if g := techList(got); !reflect.DeepEqual(g, want) {
		t.Errorf("%s: got %q, want %q", name, g, want)
	}
}

func TestConfidenceSums(t *testing.T) {
	w := testEngine(t, map[string]*Fingerprint{
		"CSP": {Headers: map[string]string{"Content-Security-Policy": `cdn\.example\.com\;confidence:50`}, HTML: []string{`<div id="example-app"\;confidence:50`}},
		// Patterns count once, as in wappalyzer, so make them differ.
		"Two": {Headers: map[string]string{"X-A": `a\;confidence:50`, "X-B": `b\;confidence:50`}},
	}, nil)
	csp := map[string][]string{"Content-Security-Policy": {"script-src cdn.example.com", "img-src cdn.example.com"}}
	checkTechs(t, "header alone, twice", w.Fingerprint(csp, nil))
	checkTechs(t, "header and html", w.Fingerprint(csp, []byte(`<div id="example-app"></div>`)), "CSP")
	checkTechs(t, "one key", w.Fingerprint(map[string][]string{"X-A": {"a"}, "X-C": {"b"}}, nil))
	checkTechs(t, "both keys", w.Fingerprint(map[string][]string{"X-A": {"a"}, "X-B": {"b"}}, nil), "Two")
}

func TestImplies(t *testing.T) {
	w := testEngine(t, map[string]*Fingerprint{
		"A":         {HTML: []string{"app-a"}, Implies: []string{`Weak\;confidence:50`, `Versioned\;version:2.1`, `Bad\;confidence:high`, "Unknown"}},
		"Weak":      {},
		"Versioned": {Implies: []string{"Deep"}},
		"Deep":      {},
		"Bad":       {},
		"Half":      {HTML: []string{`app-half\;confidence:50`}, Implies: []string{"Weak"}},
	}, nil)
	checkTechs(t, "implies", w.Fingerprint(nil, []byte("app-a")), "A", "Versioned:2.1", "Deep")
	// An implied tech is no more certain than the tech implying it.
	checkTechs(t, "uncertain parent", w.Fingerprint(nil, []byte("app-half")))
	// Two implications at 50 don't add up: the implied tech gets the best.
	checkTechs(t, "both", w.Fingerprint(nil, []byte("app-a app-half")), "A", "Versioned:2.1", "Deep")
}

func TestExcludesAndRequires(t *testing.T) {
	w := testEngine(t, map[string]*Fingerprint{
		"Main":     {Cats: []int{6}, HTML: []string{"main-app"}, Excludes: []string{"Rival"}},
		"Rival":    {HTML: []string{"rival-app"}},
		"Plugin":   {HTML: []string{"plugin-x"}, Requires: []string{"Main"}},
		"Theme":    {HTML: []string{"theme-x"}, RequiresCategory: []int{6}},
		"Implier":  {HTML: []string{"implier"}, Implies: []string{"Main"}},
		"Addon":    {HTML: []string{"addon-x"}, Requires: []string{"Plugin"}},
		"Unrelate": {Cats: []int{7}, HTML: []string{"unrelated"}},
	}, nil)
	checkTechs(t, "excludes", w.Fingerprint(nil, []byte("main-app rival-app")), "Main")
	checkTechs(t, "rival alone", w.Fingerprint(nil, []byte("rival-app")), "Rival")
	checkTechs(t, "requires unmet", w.Fingerprint(nil, []byte("plugin-x theme-x unrelated")), "Unrelate")
	checkTechs(t, "requires met", w.Fingerprint(nil, []byte("main-app plugin-x theme-x")), "Main", "Plugin", "Theme")
	checkTechs(t, "requires implied", w.Fingerprint(nil, []byte("implier plugin-x")), "Implier", "Main", "Plugin")
	checkTechs(t, "requires chain", w.Fingerprint(nil, []byte("main-app plugin-x addon-x")), "Main", "Plugin", "Addon")
}

func TestVersionSelection(t *testing.T) {
	for _, tt := range []struct{ current, found, want string }{
		{"", "1.2", "1.2"},
		{"1.2", "1.2.3", "1.2.3"},
		{"1.2.3", "1.2", "1.2.3"},
		{"", "1.2.3.4.5.6.7.8.9", ""}, // over 15 characters
		{"", "20230101", ""},          // a timestamp
		{"", "1.2 beta", ""},
		{"", " 4.0 ", "4.0"},
	} {
		if got := betterVersion(tt.current, tt.found); got != tt.want {
			t.Errorf("betterVersion(%q, %q) = %q, want %q", tt.current, tt.found, got, tt.want)
		}
	}
	w := testEngine(t, map[string]*Fingerprint{
		"V": {HTML: []string{`v-app (\d+)\;version:\1`, `v-app-full ([\d.]+)\;version:\1`}},
	}, nil)
	checkTechs(t, "best version", w.Fingerprint(nil, []byte("v-app 3 v-app-full 3.1.4")), "V:3.1.4")
}

func TestMeta(t *testing.T) {
	w := testEngine(t, map[string]*Fingerprint{
		"Exists":   {Meta: map[string][]string{"x-exists": {}}},
		"Property": {Meta: map[string][]string{"og:site_name": {`^Shop$`}}},
		"Equiv":    {Meta: map[string][]string{"x-powered": {`^Engine ([\d.]+)\;version:\1`}}},
		"Gen":      {Meta: map[string][]string{"generator": {`^Gen`}}},
	}, nil)
	body := `<html><head>
<meta name="X-Exists" content="">
<meta property="og:site_name" content="Shop">
<meta http-equiv="x-powered" content="Engine 2.0">
<meta name="generator" content="Other">
<meta name="generator" content="Gen 5">
</head></html>`
	checkTechs(t, "meta", w.Fingerprint(nil, []byte(body)), "Exists", "Property", "Equiv:2.0", "Gen")
}

func TestDOM(t *testing.T) {
	w := testEngine(t, map[string]*Fingerprint{
		"Exists":  {Dom: map[string]map[string]interface{}{"div.exists": {"exists": `\;version:2`}}},
		"Text":    {Dom: map[string]map[string]interface{}{"#footer": {"attributes": map[string]interface{}{"text": `Powered by Foo ([\d.]+)\;version:\1`}}}},
		"Or":      {Dom: map[string]map[string]interface{}{"a.or": {"text": "never", "attributes": map[string]interface{}{"href": "^/or"}}}},
		"Weak":    {Dom: map[string]map[string]interface{}{"span.weak": {"exists": `\;confidence:50`}}},
		"Missing": {Dom: map[string]map[string]interface{}{"div.missing": {"exists": ""}}},
	}, nil)
	body := `<html><body><div class="exists"></div><p id="footer"> Powered by Foo 1.4 </p>
<a class="or" href="/or/x">link</a><span class="weak"></span></body></html>`
	checkTechs(t, "dom", w.Fingerprint(nil, []byte(body)), "Exists:2", "Text:1.4", "Or")
}

func TestScriptsTextURLAndCSS(t *testing.T) {
	w := testEngine(t, map[string]*Fingerprint{
		"Inline":   {Script: []string{`inlineLib\.init\(`}},
		"Fetched":  {Script: []string{`fetchedLib\.VERSION="([\d.]+)"\;version:\1`}},
		"Text":     {Text: []string{`Powered by TextCMS`}},
		"Hidden":   {Text: []string{`secret words`}},
		"URL":      {URL: []string{`^https://shop\.example\.com/`}},
		"Style":    {CSS: []string{`\.inline-style-lib`}},
		"Sheet":    {CSS: []string{`\.sheet-lib`}},
		"Absolute": {ScriptSrc: []string{`^https://shop\.example\.com/static/abs\.js`}},
		"Raw":      {ScriptSrc: []string{`^/static/abs\.js`}},
	}, cannedTransport{
		"https://shop.example.com/static/abs.js": `fetchedLib.VERSION="1.2.3";`,
		"https://shop.example.com/css/sheet.css": `.sheet-lib{color:red}`,
	})
	body := `<html><head>
<script>inlineLib.init({})</script>
<script src="/static/abs.js"></script>
<link rel="stylesheet" href="../css/sheet.css">
<style>.inline-style-lib{}</style>
</head><body><p>Powered by TextCMS</p><div hidden>secret words</div><script>var s = "Powered by TextCMS secret words"</script></body></html>`
	got := w.FingerprintWithURL(nil, []byte(body), "https://shop.example.com/page/")
	checkTechs(t, "page", got, "Inline", "Fetched:1.2.3", "Text", "URL", "Style", "Sheet", "Absolute", "Raw")
}

func TestJSGlobals(t *testing.T) {
	w := testEngine(t, map[string]*Fingerprint{
		"Distinct": {JS: map[string]string{"__DISTINCT_STATE__": ""}},
		"Plain":    {JS: map[string]string{"plainLib.version": `([\d.]+)\;version:\1`}},
		"Valued":   {JS: map[string]string{"valuedLib": "^special$"}},
		"Var":      {JS: map[string]string{"VeryLongGlobalName": ""}},
		"Both":     {JS: map[string]string{"bothLib": ""}, HTML: []string{`both-app\;confidence:50`}},
	}, nil)
	page := func(script string) []byte { return []byte("<html><script>" + script + "</script></html>") }
	checkTechs(t, "distinctive", w.Fingerprint(nil, page(`window.__DISTINCT_STATE__ = {}`)), "Distinct")
	checkTechs(t, "bracket", w.Fingerprint(nil, page(`self["__DISTINCT_STATE__"]={}`)), "Distinct")
	checkTechs(t, "not distinctive", w.Fingerprint(nil, page(`window.plainLib = {version: "1.0"}`)))
	checkTechs(t, "constrained value", w.Fingerprint(nil, page(`globalThis.valuedLib = "special"`)))
	checkTechs(t, "top-level var", w.Fingerprint(nil, page(`var VeryLongGlobalName = 1;`)), "Var")
	checkTechs(t, "nested var", w.Fingerprint(nil, page(`function f() { var VeryLongGlobalName = 1; }`)))
	checkTechs(t, "module var", w.Fingerprint(nil, []byte(`<script type="module">var VeryLongGlobalName = 1;</script>`)))
	checkTechs(t, "read, not assigned", w.Fingerprint(nil, page(`if (window.__DISTINCT_STATE__) {}`)))
	checkTechs(t, "corroborated", w.Fingerprint(nil, append(page(`window.bothLib = {}`), "both-app"...)), "Both")
}

func TestRichResultNames(t *testing.T) {
	w := testEngine(t, map[string]*Fingerprint{
		"V": {Cats: []int{1}, Website: "https://v.example", HTML: []string{`v-app ([\d.]+)\;version:\1`}},
	}, nil)
	info := w.FingerprintWithInfo(nil, []byte("v-app 1.0"))
	if got, ok := info["V:1.0"]; !ok || got.Website != "https://v.example" {
		t.Errorf("FingerprintWithInfo = %v, want V:1.0 with its info", info)
	}
	cats := w.FingerprintWithCats(nil, []byte("v-app 1.0"))
	if got := cats["V:1.0"].Cats; !reflect.DeepEqual(got, []int{1}) {
		t.Errorf("FingerprintWithCats = %v, want V:1.0 in category 1", cats)
	}
}

func TestInvalidModifiersDropPatterns(t *testing.T) {
	_, dropped := compileFingerprints(map[string]*Fingerprint{
		"A": {HTML: []string{`a-app\;confidence:most`, `b-app\;confidence:-5`, `c-app`}},
	})
	if len(dropped) != 2 {
		t.Errorf("dropped %q, want the 2 patterns with invalid confidences", dropped)
	}
}

func TestSplitSetCookie(t *testing.T) {
	got := splitSetCookie("a=1; Expires=Thu, 01 Jan 2030 00:00:00 GMT; Path=/, b=2, c=3; Path=/")
	want := []string{"a=1; Expires=Thu, 01 Jan 2030 00:00:00 GMT; Path=/", " b=2", " c=3; Path=/"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("splitSetCookie = %q, want %q", got, want)
	}
}

func TestVisibleText(t *testing.T) {
	w := testEngine(t, map[string]*Fingerprint{
		"T": {Text: []string{`Built with Foo`}},
	}, nil)
	checkTechs(t, "across elements", w.Fingerprint(nil, []byte(`<body><p>Built <b>with</b>
Foo</p></body>`)), "T")
	checkTechs(t, "hidden", w.Fingerprint(nil, []byte(`<body><p style="display: none">Built with Foo</p></body>`)))
}
