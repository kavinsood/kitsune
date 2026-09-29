package profiler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/format"
	"os"
	"sort"
	"strings"
	"testing"
)

func readAsset(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("../../assets/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestGeneratedFingerprintsUpToDate checks that zz_generated_fingerprints.go
// is what go generate produces from the current assets and code.
func TestGeneratedFingerprintsUpToDate(t *testing.T) {
	if !unboundedRepeats {
		t.Skip("KITSUNE_BOUNDED_REPEATS is set")
	}
	src, err := GenerateFingerprintsSource(readAsset(t, "fingerprints_data.json"), readAsset(t, "categories_data.json"))
	if err != nil {
		t.Fatal(err)
	}
	if src, err = format.Source(src); err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile("zz_generated_fingerprints.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(src, current) {
		t.Fatal("zz_generated_fingerprints.go is stale; run go generate ./internal/profiler")
	}
}

// compileAssets compiles the embedded fingerprints JSON at run time, as
// NewFromFile does.
func compileAssets(t *testing.T) *CompiledFingerprints {
	var fps Fingerprints
	if err := json.Unmarshal(readAsset(t, "fingerprints_data.json"), &fps); err != nil {
		t.Fatal(err)
	}
	f, _ := compileFingerprints(fps.Apps)
	return f
}

// TestGeneratedFingerprintsMatchJSON checks that the generated fingerprints
// are the same as those compiled from JSON at run time.
func TestGeneratedFingerprintsMatchJSON(t *testing.T) {
	if !unboundedRepeats {
		t.Skip("KITSUNE_BOUNDED_REPEATS is set")
	}
	want := dumpCompiled(compileAssets(t))
	if got := dumpCompiled(decodeGenerated(t)); got != want {
		t.Fatal("generated fingerprints differ from those compiled from JSON")
	}
	if got, want := dumpNils(decodeGenerated(t)), dumpNils(compileAssets(t)); got != want {
		t.Fatal("generated fingerprints differ in nil lists from those compiled from JSON")
	}
	if got := fmt.Sprint(categoriesMapping); got != fmt.Sprint(mustParseCategories(t)) {
		t.Fatalf("categories differ")
	}
}

// decodeGenerated decodes the generated fingerprints.
func decodeGenerated(t *testing.T) *CompiledFingerprints {
	f, err := decodeFingerprints(generatedFingerprints, generatedFingerprintText)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// dumpNils returns which of the lists that are encoded differently in API
// responses or behave differently when nil are nil, which dumpCompiled
// doesn't show.
func dumpNils(f *CompiledFingerprints) string {
	var b strings.Builder
	for _, fp := range f.Apps {
		fmt.Fprintf(&b, "%s %v %v", fp.name, fp.cats == nil, fp.implies == nil)
		for _, rule := range fp.dom {
			fmt.Fprintf(&b, " %v", rule.sel.literals == nil)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func mustParseCategories(t *testing.T) map[int]categoryItem {
	c, err := parseCategories(readAsset(t, "categories_data.json"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestBoundedRepeats checks that with KITSUNE_BOUNDED_REPEATS set New gets
// the same fingerprints as compiling them from JSON.
func TestBoundedRepeats(t *testing.T) {
	old := unboundedRepeats
	unboundedRepeats = false
	defer func() { unboundedRepeats = old }()
	want := dumpCompiled(compileAssets(t))
	if got := dumpCompiled(decodeGenerated(t).withBoundedRepeats()); got != want {
		t.Fatal("bounded generated fingerprints differ from those compiled from JSON")
	}
}

// TestNewFromFile checks that NewFromFile with the embedded fingerprints'
// JSON gives the same fingerprints as New, with and without loading the
// embedded ones.
func TestNewFromFile(t *testing.T) {
	want := dumpCompiled(embeddedFingerprints())
	for _, loadEmbedded := range []bool{false, true} {
		w, err := NewFromFile("../../assets/fingerprints_data.json", loadEmbedded, true)
		if err != nil {
			t.Fatal(err)
		}
		if got := dumpCompiled(w.fingerprints); got != want {
			t.Errorf("loadEmbedded=%v: fingerprints differ from New's", loadEmbedded)
		}
		if n := len(w.GetFingerprints().Apps); n != len(decodeGenerated(t).Apps) {
			t.Errorf("loadEmbedded=%v: GetFingerprints has %d apps, want %d", loadEmbedded, n, len(decodeGenerated(t).Apps))
		}
	}
	w, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if n := len(w.GetFingerprints().Apps); n != len(decodeGenerated(t).Apps) {
		t.Errorf("New: GetFingerprints has %d apps, want %d", n, len(decodeGenerated(t).Apps))
	}
}

// TestDOMRuleWithBadRegexDropped checks that a dom rule is dropped as a
// whole when one of its checks' regexes doesn't compile, rather than losing
// just that check and matching every element the selector finds.
func TestDOMRuleWithBadRegexDropped(t *testing.T) {
	f, dropped := compileFingerprints(map[string]*Fingerprint{"App": {Dom: map[string]map[string]interface{}{
		"style":  {"text": "/sites/(?!default/)"},
		"a[x]":   {"attributes": map[string]interface{}{"href": "ok", "title": "(?!bad)"}},
		"link":   {"exists": ""},
		"script": {"text": "fine"},
	}}})
	var got []string
	for _, rule := range f.Apps[0].dom {
		got = append(got, rule.sel.selector)
	}
	if fmt.Sprint(got) != "[link script]" || len(dropped) != 2 {
		t.Errorf("got rules %v, dropped %q; want rules [link script] and 2 dropped", got, dropped)
	}
	// This regex compiles, but not with its repeats bounded.
	old := unboundedRepeats
	defer func() { unboundedRepeats = old }()
	unboundedRepeats = true
	p := mustParse(t, `([\d]+(?:\.[\d]+)*)`)
	unboundedRepeats = false
	f = &CompiledFingerprints{Apps: []*CompiledFingerprint{{name: "App", dom: []domRule{{
		sel:    newDOMSelector("p"),
		checks: []domCheck{{name: "text", pattern: p}},
	}}}}}
	if n := len(f.withBoundedRepeats().Apps[0].dom); n != 0 {
		t.Errorf("bounded: %d dom rules, want 0", n)
	}
}

func mustParse(t *testing.T, raw string) *ParsedPattern {
	t.Helper()
	p, err := ParsePattern(raw)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestDumpCompiled writes the compiled fingerprints of New to the file
// named by KITSUNE_DUMP, for comparison across changes.
func TestDumpCompiled(t *testing.T) {
	out := os.Getenv("KITSUNE_DUMP")
	if out == "" {
		t.Skip("KITSUNE_DUMP not set")
	}
	e, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, []byte(dumpCompiled(e.fingerprints)), 0o644); err != nil {
		t.Fatal(err)
	}
}

func dumpPattern(p *ParsedPattern) string {
	if p == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%q c=%d v=%q skip=%v lits=%q", p.src, p.Confidence, p.Version, p.SkipRegex, [][]string(p.literals))
}

func uniqueSorted(list []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range list {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// dumpCompiled returns a text form of everything in f that affects
// detection.
func dumpCompiled(f *CompiledFingerprints) string {
	var b strings.Builder
	for _, fp := range f.Apps {
		d, w, i, cpe := fp.appInfo()
		fmt.Fprintf(&b, "APP %q cats=%v implies=%q d=%q w=%q i=%q cpe=%q\n", fp.name, fp.cats, fp.implies, d, w, i, cpe)
		keyed := func(kind string, kps []keyedPattern) {
			for _, kp := range kps {
				fmt.Fprintf(&b, " %s %q %s\n", kind, kp.key, dumpPattern(kp.pattern))
			}
		}
		multiKeyed := func(kind string, kps []keyedPatterns) {
			for _, kp := range kps {
				fmt.Fprintf(&b, " %s %q n=%d\n", kind, kp.key, len(kp.patterns))
				for _, p := range kp.patterns {
					fmt.Fprintf(&b, "  %s\n", dumpPattern(p))
				}
			}
		}
		list := func(kind string, ps []*ParsedPattern) {
			for _, p := range ps {
				fmt.Fprintf(&b, " %s %s\n", kind, dumpPattern(p))
			}
		}
		keyed("cookie", fp.cookies)
		keyed("js", fp.js)
		keyed("header", fp.headers)
		multiKeyed("meta", fp.meta)
		multiKeyed("dns", fp.dns)
		list("html", fp.html)
		list("script", fp.script)
		list("scriptSrc", fp.scriptSrc)
		list("robots", fp.robots)
		list("cert", fp.certIssuer)
		list("css", fp.css)
		for _, rule := range fp.dom {
			fmt.Fprintf(&b, " dom %q lits=%q\n", rule.sel.selector, rule.sel.literals)
			for _, check := range rule.checks {
				fmt.Fprintf(&b, "  %q %s\n", check.name, dumpPattern(check.pattern))
			}
		}
	}
	lists := f.literalLists()
	for _, p := range []struct {
		part part
		lits []string
	}{{htmlPart, lists.html}, {cssPart, lists.css}, {robotsPart, lists.robots}} {
		fmt.Fprintf(&b, "PARTLITS %d %q\n", p.part, uniqueSorted(p.lits))
	}
	fmt.Fprintf(&b, "DOMLITS %q\n", uniqueSorted(lists.dom))
	fmt.Fprintf(&b, "JSGLOBALS %q\n", uniqueSorted(lists.jsGlobals))
	var cats []string
	for id, c := range categoriesMapping {
		cats = append(cats, fmt.Sprintf("%d=%q/%d", id, c.Name, c.Priority))
	}
	sort.Strings(cats)
	fmt.Fprintf(&b, "CATS %v\n", cats)
	return b.String()
}
