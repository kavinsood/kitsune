package profiler

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestAsciiLower(t *testing.T) {
	tests := []struct {
		in, want string
		hazard   bool
	}{
		{"", "", false},
		{"abc", "abc", false},
		{"AbC-Ü", "abc-Ü", false},
		{"Mißverständnis ÉTÉ", "mißverständnis ÉtÉ", false},
		{"5 \u212a", "5 \u212a", true},
		{"Claſs", "claſs", true},
		{"\xe2\x84", "\xe2\x84", false},
	}
	for _, tt := range tests {
		got, hazard := asciiLower(tt.in)
		if got != tt.want || hazard != tt.hazard {
			t.Errorf("asciiLower(%q) = %q, %v; want %q, %v", tt.in, got, hazard, tt.want, tt.hazard)
		}
	}
}

func TestLowerRegex(t *testing.T) {
	tests := []struct {
		src string
		// lowered is the lowered regex, or "" if there is none.
		lowered string
	}{
		{`(?i)Foo\.Bar`, `foo\.bar`},
		{`(?i)[A-Z]+_x`, `[A-Za-z\x{17f}\x{212a}]+_x`},
		{`(?i)café`, `(?i:caf)(?i:é)`},
		{`(?i)foo(?-i:Bar)`, ""},
		{`(?i)foo(?-i:[a-z])`, ""},
		{`(?i)foo(?-i:[0-9_])`, `foo[0-9_]`},
		{`(?i)foo(?-i:é)`, `fooé`},
	}
	for _, tt := range tests {
		re := lowerRegex(tt.src, false)
		got := ""
		if re != nil {
			got = re.String()
		}
		// Literals may be split differently; compare by behavior below
		// where the exact form doesn't matter.
		if (got == "") != (tt.lowered == "") {
			t.Errorf("lowerRegex(%q) = %q, want %q", tt.src, got, tt.lowered)
		}
	}
	if re := lowerRegex(`(?i)Foo\.Bar`, false); re == nil || re.String() != `foo\.bar` {
		t.Errorf("lowerRegex(Foo\\.Bar) = %v, want foo\\.bar", re)
	}
	if re := lowerRegex(`(?i)Kiss\.js`, true); re == nil || re.String() != "[kK]i[sſ][sſ]\\.j[sſ]" {
		t.Errorf("lowerRegex(Kiss\\.js, hazard) = %v", re)
	}
}

// TestEvaluateLowered checks that evaluateLowered agrees with Evaluate,
// versions (with their case) included.
func TestEvaluateLowered(t *testing.T) {
	patterns := []string{
		`jQuery v(\d+\.\d+\.\d+[\w.-]*)\;version:\1`,
		`build-([A-Z]+)-x\;version:\1`,
		`\bReact\b`,
		`caf[eé] (\w+)\;version:\1`,
		`[A-Z]{3}\d`,
		`foo(?-i:Bar)`,
		`(?:abc|DEF)+\s*=`,
		`class=(\w+)\;version:\1`,
		`\bsk\w*\b`,
		`[^\w]Ks`,
	}
	inputs := []string{
		"/*! jQuery v3.7.1-RC1 | (c) OpenJS */",
		"x BUILD-ABC-X y",
		"a REACT b react",
		"CAFÉ Noir, café Au",
		"xx ABC1 yy",
		"fooBar FOOBAR",
		"ABCdef =",
		"nothing here",
		// Fold hazards: 'ſ' folds to 's' and the Kelvin sign to 'k'.
		"Claſs=Xſ1",
		"CLASS=ſK",
		"a ſKip ſkip b",
		"a Kip ſK",
		"-Kſ -KS",
	}
	for _, src := range patterns {
		p, err := ParsePattern(src)
		if err != nil {
			t.Fatal(err)
		}
		for _, in := range inputs {
			for _, s := range []string{in, strings.Repeat("Q", 5000) + in} {
				lowered, hazard := asciiLower(s)
				ok1, v1 := p.Evaluate(s, time.Second)
				// The hazard form is valid for every target.
				for _, h := range []bool{hazard, true} {
					ok2, v2 := p.evaluateLowered(s, lowered, h, time.Second)
					if ok1 != ok2 || v1 != v2 {
						t.Errorf("%q on %q (hazard %v): Evaluate = %v %q, evaluateLowered = %v %q", src, in, h, ok1, v1, ok2, v2)
					}
				}
			}
		}
	}
}

// TestLoweredSoundOnCorpus checks that, on the corpus inputs, every
// pattern that passes its prefilter gives the same result with its lowered
// regex as with its regex. With KITSUNE_LOWERED_ALL set it checks every
// pattern, which takes minutes.
func TestLoweredSoundOnCorpus(t *testing.T) {
	all := os.Getenv("KITSUNE_LOWERED_ALL") != ""
	sites := loadCorpus(t)
	engine, err := New()
	if err != nil {
		t.Fatal(err)
	}
	inputs := map[part][]string{}
	for _, s := range sites {
		inputs[htmlPart] = append(inputs[htmlPart], string(s.body))
		for u, e := range s.files {
			switch {
			case strings.Contains(e.ContentType, "css"):
				inputs[cssPart] = append(inputs[cssPart], string(s.data[u]))
			case strings.Contains(e.ContentType, "javascript"):
				inputs[scriptPart] = append(inputs[scriptPart], string(s.data[u]))
			}
		}
	}
	checked, lowered, hazards := 0, 0, 0
	for part, list := range inputs {
		for _, in := range list {
			low, hazard := asciiLower(in)
			if hazard {
				hazards++
			}
			pre := prefilterInput(in)
			has := func(lit string) bool { return strings.Contains(pre, lit) }
			for _, fp := range engine.fingerprints.Apps {
				for _, p := range patternsOf(fp, part) {
					if !all && !p.mayMatch(has) {
						continue
					}
					checked++
					if p.loweredRe(hazard) != nil {
						lowered++
					}
					ok1, v1 := p.Evaluate(in, time.Second)
					// The hazard form is valid for every target.
					for _, h := range []bool{hazard, true} {
						ok2, v2 := p.evaluateLowered(in, low, h, time.Second)
						if ok1 != ok2 || v1 != v2 {
							t.Errorf("%s %q (hazard %v): Evaluate = %v %q, evaluateLowered = %v %q", fp.name, p.src, h, ok1, v1, ok2, v2)
						}
					}
				}
			}
		}
	}
	t.Logf("%d evaluations checked, %d with a lowered regex; %d inputs with fold hazards", checked, lowered, hazards)
}
