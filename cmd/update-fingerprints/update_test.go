package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestFixRegex(t *testing.T) {
	tests := []struct {
		in, want string
		changed  bool
		fails    bool
	}{
		{in: `jquery\.js`, want: `jquery\.js`},
		{in: `\lpmotor\.ru`, want: `lpmotor\.ru`, changed: true},
		{in: "\\u00e9t\\u00e9", want: `\x{00e9}t\x{00e9}`, changed: true},
		{in: `[\d\.-\w]+`, want: `[\d\.\-\w]+`, changed: true},
		{in: `[\w-]+`, want: `[\w-]+`},
		{in: `a{2000}`, want: `a{1000}`, changed: true},
		{in: `foo(?=bar)`, want: `foo(?:bar)`, changed: true},
		{in: `foo(?!bar)baz`, want: `foobaz`, changed: true},
		{in: `(a)\1`, fails: true},
	}
	for _, tt := range tests {
		res := fixRegex(tt.in)
		if tt.fails {
			if res.err == nil {
				t.Errorf("fixRegex(%q) = %q, want an error", tt.in, res.regex)
			}
			continue
		}
		if res.err != nil || res.regex != tt.want || (len(res.changes) > 0) != tt.changed {
			t.Errorf("fixRegex(%q) = %q, %v, %v; want %q, changed %v", tt.in, res.regex, res.changes, res.err, tt.want, tt.changed)
		}
	}
}

func TestFixModifierSeparator(t *testing.T) {
	got, fixed := fixModifierSeparator(`foo\.js;version:\1`)
	if got != `foo\.js\;version:\1` || !fixed {
		t.Errorf("got %q, %v", got, fixed)
	}
	if got, fixed := fixModifierSeparator(`foo\;confidence:50`); got != `foo\;confidence:50` || fixed {
		t.Errorf("got %q, %v", got, fixed)
	}
}

func TestCombinePatterns(t *testing.T) {
	tests := []struct{ a, b, want string }{
		{"x", "x", "x"},
		{"", "x", ""},
		{"x", "", ""},
		{`x\;version:\1`, "y", `x\;version:\1`},
		{"x", `y\;confidence:50`, "x"},
		{"(?:x)|(?:y)", "y", "(?:x)|(?:y)"},
		{"x", "y", "(?:x)|(?:y)"},
	}
	for _, tt := range tests {
		if got := combinePatterns(tt.a, tt.b, "headers", make(counter)); got != tt.want {
			t.Errorf("combinePatterns(%q, %q) = %q, want %q", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestSplitSelector(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"a, b", []string{"a", "b"}},
		{"a[title='x, y'], b", []string{"a[title='x, y']", "b"}},
		{"div:not(.a, .b)", []string{"div:not(.a, .b)"}},
	}
	for _, tt := range tests {
		if got := splitSelector(tt.in); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("splitSelector(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func normalizeJSON(t *testing.T, s string) *Tech {
	t.Helper()
	var raw rawTech
	if err := json.Unmarshal([]byte(s), &raw); err != nil {
		t.Fatal(err)
	}
	tech, err := (&normalizer{stats: make(counter), split: true}).normalize(&raw)
	if err != nil {
		t.Fatal(err)
	}
	return tech
}

func TestMergeTech(t *testing.T) {
	hi := normalizeJSON(t, `{"cats":[1],"html":"a","headers":{"X-A":"1"},"requires":"R","dom":{"#x":{"text":"t"}}}`)
	lo := normalizeJSON(t, `{"cats":[2],"html":["b","a"],"headers":{"x-a":"2","x-b":""},"requires":"S","excludes":"E","dom":["#x","#y, #z"]}`)
	mergeTech(hi, lo, make(counter))
	if !reflect.DeepEqual(hi.Cats, []int{1}) {
		t.Errorf("cats = %v", hi.Cats)
	}
	if !reflect.DeepEqual(hi.HTML, []string{"a", "b"}) {
		t.Errorf("html = %v", hi.HTML)
	}
	if want := map[string]string{"x-a": "(?:1)|(?:2)", "x-b": ""}; !reflect.DeepEqual(hi.Headers, want) {
		t.Errorf("headers = %v", hi.Headers)
	}
	// Gates come from the highest-ranked source that has them.
	if !reflect.DeepEqual(hi.Requires, []string{"R"}) || !reflect.DeepEqual(hi.Excludes, []string{"E"}) {
		t.Errorf("requires = %v, excludes = %v", hi.Requires, hi.Excludes)
	}
	if c := hi.DOM["#x"]; c == nil || c.Text == nil || *c.Text != "t" {
		t.Errorf("dom #x = %+v", c)
	}
	for _, sel := range []string{"#y", "#z"} {
		if hi.DOM[sel] == nil {
			t.Errorf("dom %s missing", sel)
		}
	}
}

func TestCheckMatchesAnything(t *testing.T) {
	techs := map[string]*Tech{
		"A": {Cats: []int{1}, HTML: []string{`x?`, `y`, `\;confidence:50`}, Implies: []string{"A", `B\;confidence:50`}},
	}
	l := newLinter()
	l.check(techs, map[string]*Category{"1": {Name: "c"}})
	kinds := make(counter)
	for _, i := range l.issues {
		kinds[i.kind]++
	}
	if want := (counter{"matches-anything": 2, "self-implies": 1, "missing-tech": 1}); !reflect.DeepEqual(kinds, want) {
		t.Errorf("issues = %v, want %v", l.issues, want)
	}
}

func TestApplyOverrides(t *testing.T) {
	techs := map[string]*Tech{
		"A":    normalizeJSON(t, `{"cats":[1],"html":["a","b"],"meta":{"generator":["x","y"]},"dom":"#a, #b","headers":{"server":"s\\;version:\\1"}}`),
		"Gone": normalizeJSON(t, `{"cats":[1],"html":"g"}`),
	}
	ovr := `{
		"_comment": "test",
		"remove": {"Gone": true, "A": {"html": "a", "meta": {"generator": "x"}, "dom": "#a, #b", "js": {"missing": ""}}},
		"set": {"A": {"scriptSrc": ["s\\.js"]}},
		"add": {"A": {"html": "c", "requires": "B"}, "B": {"cats": [1], "html": "bb"}}
	}`
	file := filepath.Join(t.TempDir(), "overrides.json")
	if err := os.WriteFile(file, []byte(ovr), 0o644); err != nil {
		t.Fatal(err)
	}
	l := newLinter()
	if _, err := applyOverrides(file, techs, l); err != nil {
		t.Fatal(err)
	}
	a := techs["A"]
	if techs["Gone"] != nil || techs["B"] == nil {
		t.Errorf("techs = %v", sortedKeys(techs))
	}
	if !reflect.DeepEqual(a.HTML, []string{"b", "c"}) || !reflect.DeepEqual(a.ScriptSrc, []string{`s\.js`}) ||
		!reflect.DeepEqual(a.Meta, map[string][]string{"generator": {"y"}}) || len(a.DOM) != 0 ||
		!reflect.DeepEqual(a.Requires, []string{"B"}) {
		t.Errorf("A = %+v", a)
	}
	if len(l.issues) != 1 || l.issues[0].kind != "override-noop" {
		t.Errorf("issues = %v", l.issues)
	}

	// Adding to a keyed pattern with modifiers is an error.
	bad := `{"add": {"A": {"headers": {"server": "t"}}}}`
	if err := os.WriteFile(file, []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := applyOverrides(file, techs, newLinter()); err == nil {
		t.Error("conflicting add: no error")
	}
	// Invalid regexes in set are errors.
	bad = `{"set": {"A": {"html": "(?<=x)"}}}`
	if err := os.WriteFile(file, []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := applyOverrides(file, techs, newLinter()); err == nil {
		t.Error("invalid regex: no error")
	}
}

func TestOpenZipCRX(t *testing.T) {
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	w, _ := zw.Create("manifest.json")
	w.Write([]byte(`{"version":"1.2.3"}`))
	zw.Close()

	header := []byte("proto-header")
	crx := []byte("Cr24")
	crx = binary.LittleEndian.AppendUint32(crx, 3)
	crx = binary.LittleEndian.AppendUint32(crx, uint32(len(header)))
	crx = append(append(crx, header...), zbuf.Bytes()...)

	for name, data := range map[string][]byte{"zip": zbuf.Bytes(), "crx3": crx} {
		r, err := openZip(data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if v := manifestVersion(r); v != "1.2.3" {
			t.Errorf("%s: manifest version %q, want 1.2.3", name, v)
		}
	}
	if _, err := openZip(crx[:20]); err == nil {
		t.Error("truncated CRX opened")
	}
}

func TestRankExtensions(t *testing.T) {
	sources := []*source{
		{name: "chrome", manifest: "6.12.7"},
		{name: "extension", manifest: "6.12.10"},
		{name: "enthec"},
	}
	rankExtensions(sources)
	var got []string
	for _, s := range sources {
		got = append(got, s.name)
	}
	if want := "extension,chrome,enthec"; strings.Join(got, ",") != want {
		t.Errorf("got %s, want %s", strings.Join(got, ","), want)
	}
}
