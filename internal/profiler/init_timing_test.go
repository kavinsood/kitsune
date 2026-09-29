package profiler

import (
	"encoding/json"
	"os"
	"regexp"
	"runtime"
	"testing"
	"time"

	"github.com/kavinsood/kitsune/assets"
)

// TestInitTiming reports the cost of New(): the first call is cold, later
// ones warm. Run with KITSUNE_INIT_TIMING=1, natively or under
// GOOS=js GOARCH=wasm (with $(go env GOROOT)/lib/wasm on PATH).
func TestInitTiming(t *testing.T) {
	if os.Getenv("KITSUNE_INIT_TIMING") == "" {
		t.Skip("KITSUNE_INIT_TIMING not set")
	}
	var engines []*Wappalyze
	for i := 0; i < 5; i++ {
		start := time.Now()
		e, err := New()
		if err != nil {
			t.Fatal(err)
		}
		elapsed := time.Since(start)
		engines = append(engines, e)
		var ms runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&ms)
		t.Logf("New() #%d: %v  heap after GC: %.1fMB (%d engines live)", i, elapsed, float64(ms.HeapAlloc)/(1<<20), len(engines))
	}
	engines = []*Wappalyze{engines[0]}
	var ms runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&ms)
	t.Logf("heap with 1 engine: %.1fMB", float64(ms.HeapAlloc)/(1<<20))
	runtime.KeepAlive(engines)
}

// TestInitPhases reports the cost of the lazily built structures, which is
// paid by the first request instead of New, and of compiling the
// fingerprints from JSON as NewFromFile does.
func TestInitPhases(t *testing.T) {
	if os.Getenv("KITSUNE_INIT_TIMING") == "" {
		t.Skip("KITSUNE_INIT_TIMING not set")
	}
	for i := 0; i < 3; i++ {
		td := time.Now()
		g, err := decodeFingerprints(generatedFingerprints, generatedFingerprintText)
		if err != nil {
			t.Fatal(err)
		}
		t0 := time.Now()
		f := g
		f.literalLists()
		tl := time.Now()
		f.literalMatcher(htmlPart)
		t1 := time.Now()
		f.domLiteralMatcher()
		t2 := time.Now()
		f.hasJSGlobal("x")
		t3 := time.Now()
		seen := map[*domSelector]bool{}
		for _, fp := range g.Apps {
			for _, rule := range fp.dom {
				if !seen[rule.sel] {
					seen[rule.sel] = true
					rule.sel.compiled()
				}
			}
		}
		n := len(seen)
		t4 := time.Now()
		var srcs []string
		for _, fp := range g.Apps {
			fp.mapPatterns(func(p *ParsedPattern, _ bool) *ParsedPattern {
				if p.src != "" {
					srcs = append(srcs, p.src)
				}
				return p
			})
		}
		t5 := time.Now()
		for _, src := range srcs {
			regexp.MustCompile(src)
		}
		t6 := time.Now()
		var fps Fingerprints
		if err := json.Unmarshal([]byte(assets.FingerprintsJSON), &fps); err != nil {
			t.Fatal(err)
		}
		t7 := time.Now()
		compileFingerprints(fps.Apps)
		t8 := time.Now()
		t.Logf("decode %v | lazy: literalLists %v literalMatchers %v domLiterals %v jsGlobals %v | all %d selectors %v | all %d regexes %v | JSON path: unmarshal %v compile %v",
			t0.Sub(td), tl.Sub(t0), t1.Sub(tl), t2.Sub(t1), t3.Sub(t2), n, t4.Sub(t3), len(srcs), t6.Sub(t5), t7.Sub(t6), t8.Sub(t7))
	}
}
