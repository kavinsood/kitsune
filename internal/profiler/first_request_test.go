package profiler

import (
	"os"
	"strconv"
	"testing"
	"time"
)

// TestFirstRequest reports how much of the work New no longer does up front
// lands on the first request: it analyzes corpus site KITSUNE_FIRST_SITE (an
// index, default 0) in a fresh process, then again warm, and counts the
// regexes and selectors compiled on the way. Run it in a separate process
// per site, since the lazily built state is shared:
//
//	KITSUNE_INIT_TIMING=1 KITSUNE_CORPUS=/tmp/kitsune-corpus KITSUNE_FIRST_SITE=0 go test -count=1 -run TestFirstRequest -v ./internal/profiler
func TestFirstRequest(t *testing.T) {
	if os.Getenv("KITSUNE_INIT_TIMING") == "" {
		t.Skip("KITSUNE_INIT_TIMING not set")
	}
	sites := loadCorpus(t)
	withOfflineCorpus(t, sites)
	i, _ := strconv.Atoi(os.Getenv("KITSUNE_FIRST_SITE"))
	s := sites[i]

	start := time.Now()
	engine, err := New()
	if err != nil {
		t.Fatal(err)
	}
	newTime := time.Since(start)
	var times []time.Duration
	for run := 0; run < 4; run++ {
		start := time.Now()
		engine.FingerprintWithInfoAndURL(s.Headers, s.body, s.URL)
		times = append(times, time.Since(start))
		if run == 0 {
			regexes, selectors := lazyCompiled(engine.fingerprints)
			t.Logf("after first request: %d regexes and %d selectors compiled", regexes, selectors)
		}
	}
	t.Logf("%s: New %v, first request %v, then %v %v %v", s.URL, newTime, times[0], times[1], times[2], times[3])
}

// lazyCompiled returns the numbers of distinct regexes and selectors of f
// compiled so far.
func lazyCompiled(f *CompiledFingerprints) (regexes, selectors int) {
	seenPatterns := map[*ParsedPattern]bool{}
	seenSelectors := map[*domSelector]bool{}
	for _, fp := range f.Apps {
		fp.mapPatterns(func(p *ParsedPattern, _ bool) *ParsedPattern {
			if !seenPatterns[p] && p.regex != nil {
				regexes++
			}
			seenPatterns[p] = true
			return p
		})
		for _, rule := range fp.dom {
			if !seenSelectors[rule.sel] && rule.sel.matcher != nil {
				selectors++
			}
			seenSelectors[rule.sel] = true
		}
	}
	return regexes, selectors
}
