package profiler

// Cost of matching fetched JS, over the scripts of the offline corpus (see
// corpus_bench_test.go), capped as the asset fetcher caps them:
//
//	KITSUNE_CORPUS=/tmp/kitsune-corpus go test ./internal/profiler -run TestFetchedJSCost -v
//	KITSUNE_CORPUS=/tmp/kitsune-corpus go test ./internal/profiler -run '^$' -bench BenchmarkFetchedJS -benchmem

import (
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// corpusScripts returns the JS a page's fetch would match: the scripts of
// the corpus entries served as JavaScript, cut at maxAssetBytes (or
// KITSUNE_JS_CAP).
func corpusScripts(s *loadedSite) []string {
	jsCap := maxAssetBytes
	if n, err := strconv.Atoi(os.Getenv("KITSUNE_JS_CAP")); err == nil {
		jsCap = n
	}
	var scripts []string
	for _, e := range s.Entries {
		ct := e.ContentType
		if e.Status != 200 || !strings.Contains(ct, "javascript") && !strings.Contains(ct, "text/plain") {
			continue
		}
		data := s.data[e.URL]
		if len(data) > jsCap {
			data = data[:jsCap]
		}
		scripts = append(scripts, string(data))
	}
	return scripts
}

// TestFetchedJSCost reports, per site, the JS scanned and where matching
// it spends its time: lowering for the prefilter, the literal scan, the
// regexes that pass the prefilter, and the window-assignment scan. With
// KITSUNE_JS_CAP set to a size in bytes, scripts are cut at it instead of
// maxAssetBytes.
func TestFetchedJSCost(t *testing.T) {
	sites := loadCorpus(t)
	engine, err := New()
	if err != nil {
		t.Fatal(err)
	}
	f := engine.fingerprints
	m := f.literalMatcher(scriptPart)
	// Warm up lazy compilation so it isn't counted.
	for _, s := range sites {
		for _, js := range corpusScripts(s) {
			f.matchString(js, scriptPart, engine.regexTimeout)
		}
	}
	type patternCost struct {
		app  string
		src  string
		d    time.Duration
		runs int
	}
	costs := map[*ParsedPattern]*patternCost{}
	var total struct {
		bytes                    int
		lower, scan, regex, glob time.Duration
	}
	for _, s := range sites {
		var bytes, runs, hits int
		var lower, scan, regex, glob time.Duration
		for _, js := range corpusScripts(s) {
			bytes += len(js)
			// As matchString does.
			start := time.Now()
			lowered, hazard := asciiLower(js)
			pre := lowered
			if hazard {
				pre = prefilterInput(js)
			}
			lower += time.Since(start)
			start = time.Now()
			has := m.scan(pre)
			scan += time.Since(start)
			for _, fp := range f.Apps {
				for _, p := range fp.script {
					if !p.mayMatch(has) {
						continue
					}
					start = time.Now()
					ok, _ := p.evaluateLowered(js, lowered, hazard, engine.regexTimeout)
					d := time.Since(start)
					regex += d
					runs++
					if ok {
						hits++
					}
					c := costs[p]
					if c == nil {
						c = &patternCost{app: fp.name, src: p.src}
						costs[p] = c
					}
					c.d += d
					c.runs++
				}
			}
			start = time.Now()
			f.matchJSGlobals(js, false)
			glob += time.Since(start)
		}
		t.Logf("%-20s %6.2fMB JS  lower %5.1fms  scan %5.1fms  regex %6.1fms (%d runs, %d hits)  globals %5.1fms",
			siteDirName(s.URL), float64(bytes)/(1<<20), ms(lower), ms(scan), ms(regex), runs, hits, ms(glob))
		total.bytes += bytes
		total.lower += lower
		total.scan += scan
		total.regex += regex
		total.glob += glob
	}
	t.Logf("%-20s %6.2fMB JS  lower %5.1fms  scan %5.1fms  regex %6.1fms  globals %5.1fms",
		"total", float64(total.bytes)/(1<<20), ms(total.lower), ms(total.scan), ms(total.regex), ms(total.glob))
	var list []*patternCost
	for _, c := range costs {
		list = append(list, c)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].d > list[j].d })
	for _, c := range list[:min(len(list), 15)] {
		t.Logf("  %6.1fms %3d runs  %-18s %.90s", ms(c.d), c.runs, c.app, c.src)
	}
	n := 0
	for _, fp := range f.Apps {
		n += len(fp.script)
	}
	t.Logf("scripts patterns: %d", n)
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// BenchmarkFetchedJS matches every fetched script of a site as
// analyzeWithPipeline does, without the network or the HTML.
func BenchmarkFetchedJS(b *testing.B) {
	sites := loadCorpus(b)
	engine, err := New()
	if err != nil {
		b.Fatal(err)
	}
	f := engine.fingerprints
	for _, s := range sites {
		scripts := corpusScripts(s)
		b.Run(siteDirName(s.URL), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				for _, js := range scripts {
					f.matchString(js, scriptPart, engine.regexTimeout)
					f.matchJSGlobals(js, false)
				}
			}
		})
	}
}

// TestCorpusPeakHeap reports, per site, the allocations of one analysis and
// the peak live heap during it (sampled), the engine included. Wasm linear
// memory never shrinks, so on the Worker the peak is what counts. The GC
// runs under the Worker's soft memory limit (see cmd/kitsune-worker).
func TestCorpusPeakHeap(t *testing.T) {
	sites := loadCorpus(t)
	defer debug.SetMemoryLimit(debug.SetMemoryLimit(80 << 20))
	withOfflineCorpus(t, sites)
	engine, err := New()
	if err != nil {
		t.Fatal(err)
	}
	// One warm-up analysis per site, so lazy compilation isn't counted.
	for _, s := range sites {
		engine.FingerprintWithInfoAndURL(s.Headers, s.body, s.URL)
	}
	for _, s := range sites {
		var ms runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&ms)
		base, before := ms.HeapAlloc, ms.TotalAlloc
		var peak atomic.Uint64
		peak.Store(base)
		done := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			var m runtime.MemStats
			for {
				select {
				case <-done:
					return
				case <-time.After(200 * time.Microsecond):
				}
				runtime.ReadMemStats(&m)
				if m.HeapAlloc > peak.Load() {
					peak.Store(m.HeapAlloc)
				}
			}
		}()
		engine.FingerprintWithInfoAndURL(s.Headers, s.body, s.URL)
		close(done)
		wg.Wait()
		runtime.ReadMemStats(&ms)
		if ms.HeapAlloc > peak.Load() {
			peak.Store(ms.HeapAlloc)
		}
		t.Logf("%-20s alloc %6.1fMB  heap: engine %5.1fMB, peak %5.1fMB", siteDirName(s.URL),
			float64(ms.TotalAlloc-before)/(1<<20), float64(base)/(1<<20), float64(peak.Load())/(1<<20))
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	t.Logf("Sys (memory obtained from the OS, a high-water mark): %.1fMB", float64(ms.Sys)/(1<<20))
}
