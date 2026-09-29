package profiler

import (
	"bytes"
	"math/rand"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
)

func TestRequiredLiterals(t *testing.T) {
	tests := []struct {
		expr  string
		lower bool
		want  literalSets
	}{
		{`babelHelpers`, false, literalSets{{"babelHelpers"}}},
		{`(?i)\.MuiPaper-root`, true, literalSets{{".muipaper-root"}}},
		{`(?i)\.MuiPaper-root`, false, nil},
		{`https?://cdn\.example\.com`, false, literalSets{{"https://cdn.example.com", "http://cdn.example.com"}}},
		{`(?:foo|bar)baz`, false, literalSets{{"foobaz", "barbaz"}}},
		{`foo.*bar`, false, literalSets{{"foo"}, {"bar"}}},
		{`foo|.*`, false, nil},
		{`(?:foo)?bar`, false, literalSets{{"foobar", "bar"}}},
		{`a+`, false, literalSets{{"a"}}},
		{`[0-9]+`, false, literalSets{{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}}},
		{`[^a]`, false, nil},
		{`x*`, false, nil},
	}
	for _, tt := range tests {
		got := requiredLiterals(tt.expr, tt.lower)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("requiredLiterals(%q, %v) = %q, want %q", tt.expr, tt.lower, got, tt.want)
		}
	}
}

func TestFoldHazard(t *testing.T) {
	// 'ſ' matches (?i)s, but strings.ToLower keeps it as 'ſ'.
	re := regexp.MustCompile(`(?i)ssl`)
	input := "ſſl"
	if !re.MatchString(input) {
		t.Fatal("expected (?i)ssl to match ſſl")
	}
	if lits := requiredLiterals(re.String(), true); lits.in(strings.ToLower(input)) {
		t.Fatal("prefilter unexpectedly passed; foldHazard handling is untested")
	}
	if !strings.Contains(strings.ToLower(input), foldHazard) {
		t.Fatal("foldHazard not detected")
	}
}

func TestLiteralMatcher(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	const alphabet = "abc-."
	randString := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = alphabet[r.Intn(len(alphabet))]
		}
		return string(b)
	}
	for iter := 0; iter < 200; iter++ {
		var lits []string
		for i := 0; i < 1+r.Intn(20); i++ {
			lits = append(lits, randString(1+r.Intn(5)))
		}
		m := newLiteralMatcher(lits)
		input := randString(r.Intn(200))
		has := m.scan(input)
		for _, lit := range lits {
			if got, want := has(lit), strings.Contains(input, lit); got != want {
				t.Fatalf("scan(%q) has(%q) = %v, want %v", input, lit, got, want)
			}
		}
		if !has("zzz") {
			t.Fatal("unknown literals must be reported present")
		}
	}
}

// TestPrefilterSoundOnCorpus checks that no regex that matches a corpus input
// is ruled out by its prefilter.
func TestPrefilterSoundOnCorpus(t *testing.T) {
	sites := loadCorpus(t)
	engine, err := New()
	if err != nil {
		t.Fatal(err)
	}
	var htmls, css, js, srcs []string
	for _, s := range sites {
		htmls = append(htmls, strings.ToLower(string(s.body)))
		for u, e := range s.files {
			srcs = append(srcs, u)
			switch {
			case strings.Contains(e.ContentType, "css"):
				css = append(css, string(s.data[u]))
			case strings.Contains(e.ContentType, "javascript"):
				js = append(js, string(s.data[u]))
			}
		}
	}
	check := func(kind string, patterns []*ParsedPattern, inputs []string, m *literalMatcher) {
		for _, in := range inputs {
			lowered := strings.ToLower(in)
			direct := func(lit string) bool { return strings.Contains(lowered, lit) }
			scanned := direct
			if m != nil {
				scanned = m.scan(lowered)
			}
			for _, p := range patterns {
				if p.regex == nil || (p.mayMatch(direct) && p.mayMatch(scanned)) {
					continue
				}
				if p.regex.MatchString(in) {
					t.Errorf("%s pattern %q matches but prefilter %q rejected it", kind, p.regex, p.literals)
				}
			}
		}
	}
	var html, cssPats, script []*ParsedPattern
	for _, fp := range engine.fingerprints.Apps {
		html = append(html, fp.html...)
		cssPats = append(cssPats, fp.css...)
		script = append(script, fp.scriptSrc...)
	}
	check("html", html, htmls, engine.fingerprints.literalMatchers[htmlPart])
	check("css", cssPats, css, engine.fingerprints.literalMatchers[cssPart])
	check("scriptSrc", script, srcs, nil)

	for _, in := range js {
		has := libraryLiterals.scan(in)
		for name, re := range libraryPatterns {
			if !re.literals.satisfied(has) && re.Regexp.MatchString(in) {
				t.Errorf("library pattern %s matches but prefilter %q rejected it", name, re.literals)
			}
		}
	}
}

func TestSelectorLiterals(t *testing.T) {
	tests := []struct {
		sel  string
		want [][]string
	}{
		{`link[href*='/wp-content/Plugins/']`, [][]string{{"/wp-content/plugins/"}}},
		{`div#Foo.bar-baz > a[target="_blank"]`, [][]string{{"foo", "bar-baz", "_blank"}}},
		{`a[href*='x.com'], .y`, [][]string{{"x.com"}, {"y"}}},
		{`input[type=hidden][name^="csrf"]`, [][]string{{"hidden", "csrf"}}},
		{`body:not(.foo) .bar`, [][]string{{"bar"}}},
		{`p:contains('a,b') .c`, [][]string{{"c"}}},
		{`a[href*='x'], div`, nil},  // one alternative has no literal
		{`a[href*='x' i]`, nil},     // case-insensitive
		{`a[href!='x']`, nil},       // negated
		{`a[href#=(x[.y])]`, nil},   // regex
		{`a[xlink|href='x']`, nil},  // namespace
		{`a[href*='\x']`, nil},      // escapes
		{`html[data-wf-site]`, nil}, // presence only
		{`a[href*='é']`, nil},       // non-ASCII
		{`a[href*='x'`, nil},        // unterminated
	}
	for _, tt := range tests {
		if got := selectorLiterals(tt.sel); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("selectorLiterals(%q) = %q, want %q", tt.sel, got, tt.want)
		}
	}
}

// TestDOMPrefilterSoundOnCorpus checks that no selector that matches a corpus
// page is skipped by its prefilter.
func TestDOMPrefilterSoundOnCorpus(t *testing.T) {
	sites := loadCorpus(t)
	engine, err := New()
	if err != nil {
		t.Fatal(err)
	}
	withLiterals := 0
	for _, sel := range engine.fingerprints.domSelectors {
		if sel.literals != nil {
			withLiterals++
		}
	}
	t.Logf("%d of %d selectors have literals", withLiterals, len(engine.fingerprints.domSelectors))
	for _, s := range sites {
		doc, err := goquery.NewDocumentFromReader(bytes.NewReader(s.body))
		if err != nil {
			t.Fatal(err)
		}
		p := engine.fingerprints.domLiterals.presence()
		for _, n := range doc.Nodes {
			addAttributeValues(p, n)
		}
		skipped := 0
		for selector, sel := range engine.fingerprints.domSelectors {
			if sel.mayMatch(p.has) {
				continue
			}
			skipped++
			if doc.Find(selector).Length() > 0 {
				t.Errorf("%s: selector %q matches but prefilter %q rejected it", s.URL, selector, sel.literals)
			}
		}
		t.Logf("%s: skipped %d selectors", s.URL, skipped)
	}
}

// checkPropWindows checks that the run-based property path extraction gives
// exactly the results of running the regexes over the whole input.
func checkPropWindows(t *testing.T, js string) {
	t.Helper()
	if got, want := propPathMatches(js), propPathPattern.FindAllStringSubmatch(js, -1); !reflect.DeepEqual(got, want) {
		t.Fatalf("propPathMatches(%.200q) = %q, want %q", js, got, want)
	}
	if got, want := propAccesses(js), propAccessPattern.FindAllString(js, -1); !reflect.DeepEqual(got, want) {
		t.Fatalf("propAccesses(%.200q) = %q, want %q", js, got, want)
	}
}

func TestPropWindows(t *testing.T) {
	for _, js := range []string{
		"", "a.b", "a.b=1", "a.b = 'x'", `a.b="c.d=1"`, "a.b==c.d", "x..a.b=1", ".a.b=1",
		"a.b.=1", "a...b=1", "$.fn.jquery='3'", "a.$=1", "$a.b$.c", "é.a.b", "a.b\n\t=\n\"\"x",
		"window.foo.bar(baz.qux)", "a.b=''\"\"", "a.b=\xff", "\xffa.b\xff",
	} {
		checkPropWindows(t, js)
	}
	r := rand.New(rand.NewSource(1))
	const alphabet = "ab_$0..  ==\"'\n\xc3\xa9;("
	for iter := 0; iter < 20000; iter++ {
		b := make([]byte, r.Intn(40))
		for i := range b {
			b[i] = alphabet[r.Intn(len(alphabet))]
		}
		checkPropWindows(t, string(b))
	}
}

func TestPrefixFind(t *testing.T) {
	for _, tt := range []struct {
		expr string
		want []string
	}{
		{`(?:mobx|action|autorun)\b`, []string{"mobx", "action", "autorun"}},
		{`(?:jest\.|describe\s*\()`, []string{"jest.", "describe"}},
		{`(ab|cd)+x`, []string{"ab", "cd"}},
		{`[ab]c`, []string{"a", "b"}},
		{`\bfoo`, nil},
		{`(?i)foo`, nil},
		{`a*b`, nil},
		{`foo|b?ar`, nil},
	} {
		re := mustCompilePrefiltered(tt.expr)
		if !reflect.DeepEqual(re.prefixes, tt.want) {
			t.Errorf("prefixes of %q = %q, want %q", tt.expr, re.prefixes, tt.want)
		}
	}

	r := rand.New(rand.NewSource(1))
	const alphabet = "abcd$_. x\n"
	for _, expr := range []string{`(?:ab|cd)\b`, `a(b|c)+`, `(?:ab|cd)(x)?`, `ab\s*(\w+)$`, `(?:a|b)(?:c|d)\b.`, `abc|a\bb`, `(?m)ab^c|ab$`, `a(?:bc|b)(d)?`} {
		re := mustCompilePrefiltered(expr)
		if re.anchored == nil {
			t.Fatalf("expected prefixes for %q", expr)
		}
		for iter := 0; iter < 5000; iter++ {
			b := make([]byte, r.Intn(30))
			for i := range b {
				b[i] = alphabet[r.Intn(len(alphabet))]
			}
			if got, want := re.find(string(b)), re.Regexp.FindStringSubmatch(string(b)); !reflect.DeepEqual(got, want) {
				t.Fatalf("%q.find(%q) = %q, want %q", expr, b, got, want)
			}
		}
	}
}

// TestPrefixFindOnCorpus checks that find gives the plain regexp's results
// for the real patterns on corpus scripts and their statements.
func TestPrefixFindOnCorpus(t *testing.T) {
	patterns := map[string]*prefilteredRegexp{
		"varDecl": varDeclPattern, "windowAssign": windowAssignPattern,
		"thisAssign": thisAssignPattern, "classAdd": classAddPattern,
	}
	for name, re := range libraryPatterns {
		patterns[name] = re
	}
	check := func(in string) {
		for name, re := range patterns {
			if got, want := re.find(in), re.Regexp.FindStringSubmatch(in); !reflect.DeepEqual(got, want) {
				t.Fatalf("%s: find = %q, want %q", name, got, want)
			}
		}
	}
	for _, s := range loadCorpus(t) {
		for u, e := range s.files {
			if !strings.Contains(e.ContentType, "javascript") {
				continue
			}
			js := string(s.data[u])
			check(js)
			for _, stmt := range SplitIntoStatements(js) {
				check(stmt)
			}
		}
	}
}

func TestPropWindowsOnCorpus(t *testing.T) {
	for _, s := range loadCorpus(t) {
		for u := range s.files {
			checkPropWindows(t, string(s.data[u]))
		}
		checkPropWindows(t, string(s.body))
	}
}
