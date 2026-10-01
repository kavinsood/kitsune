package profiler

// Offline corpus benchmark for the CPU side of analysis.
//
// Fetch a corpus once (network):
//
//	KITSUNE_CORPUS=/tmp/kitsune-corpus KITSUNE_CORPUS_FETCH=1 go test ./internal/profiler -run TestCorpusFetch -v
//
// Then run offline (all HTTP is served from the corpus, DNS is disabled):
//
//	KITSUNE_CORPUS=/tmp/kitsune-corpus go test ./internal/profiler -run TestCorpusDetections -v
//	KITSUNE_CORPUS=/tmp/kitsune-corpus go test ./internal/profiler -run '^$' -bench BenchmarkCorpus -benchmem
//
// KITSUNE_CORPUS_SITES (comma-separated URLs) replaces the list of sites.

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
)

var corpusSites = []string{
	"https://github.com/",
	"https://vercel.com/",
	"https://www.hackerone.com/",
	"https://react.dev/",
	"https://www.shopify.com/",
	// Heavy bundles: most of their analysis is matching fetched JS.
	"https://nextjs.org/",
	"https://www.gymshark.com/",
	"https://www.wix.com/",
}

type corpusEntry struct {
	URL         string `json:"url"`
	File        string `json:"file"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
}

type corpusSite struct {
	URL     string              `json:"url"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body_file"`
	Entries []corpusEntry       `json:"entries"`
}

func sitesOfCorpus() []string {
	if env := os.Getenv("KITSUNE_CORPUS_SITES"); env != "" {
		return strings.Split(env, ",")
	}
	return corpusSites
}

func corpusDir(tb testing.TB) string {
	dir := os.Getenv("KITSUNE_CORPUS")
	if dir == "" {
		tb.Skip("KITSUNE_CORPUS not set")
	}
	return dir
}

func siteDirName(u string) string {
	p, _ := url.Parse(u)
	return p.Hostname()
}

func TestCorpusFetch(t *testing.T) {
	dir := corpusDir(t)
	if os.Getenv("KITSUNE_CORPUS_FETCH") == "" {
		t.Skip("KITSUNE_CORPUS_FETCH not set")
	}
	client := &http.Client{Timeout: 20 * time.Second}
	const ua = "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5931.0 Safari/537.36"

	for _, site := range sitesOfCorpus() {
		sdir := filepath.Join(dir, siteDirName(site))
		if err := os.MkdirAll(sdir, 0o755); err != nil {
			t.Fatal(err)
		}
		// Main page: fetched like internal/api does (http.Get, default UA).
		resp, err := http.Get(site)
		if err != nil {
			t.Fatalf("%s: %v", site, err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
		resp.Body.Close()
		if err := os.WriteFile(filepath.Join(sdir, "index.html"), body, 0o644); err != nil {
			t.Fatal(err)
		}
		cs := corpusSite{URL: site, Headers: resp.Header, Body: "index.html"}

		doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		base, _ := url.Parse(site)
		type asset struct{ raw, typ string }
		var assets []asset
		doc.Find("script[src]").Each(func(_ int, s *goquery.Selection) {
			if v, _ := s.Attr("src"); v != "" {
				assets = append(assets, asset{v, "script"})
			}
		})
		doc.Find("link[rel=stylesheet][href]").Each(func(_ int, s *goquery.Selection) {
			if v, _ := s.Attr("href"); v != "" {
				assets = append(assets, asset{v, "style"})
			}
		})
		assets = append(assets, asset{"/robots.txt", "robots"})
		// GTM containers that the page refers to, which analysis fetches.
		for _, id := range gtmContainerIDs(body, maxGTMContainers) {
			assets = append(assets, asset{gtmContainerURL(id), "script"})
		}

		var mu sync.Mutex
		var wg sync.WaitGroup
		seen := map[string]bool{}
		for _, a := range assets {
			ref, err := url.Parse(a.raw)
			if err != nil {
				continue
			}
			abs := base.ResolveReference(ref).String()
			if seen[abs] {
				continue
			}
			seen[abs] = true
			wg.Add(1)
			go func(abs, typ string) {
				defer wg.Done()
				req, _ := http.NewRequest("GET", abs, nil)
				req.Header.Set("User-Agent", ua)
				switch typ {
				case "script":
					req.Header.Set("Accept", "*/*")
				case "style":
					req.Header.Set("Accept", "text/css,*/*;q=0.1")
				}
				r, err := client.Do(req)
				if err != nil {
					t.Logf("fetch %s: %v", abs, err)
					return
				}
				data, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
				r.Body.Close()
				h := sha1.Sum([]byte(abs))
				name := hex.EncodeToString(h[:8])
				if err := os.WriteFile(filepath.Join(sdir, name), data, 0o644); err != nil {
					t.Error(err)
					return
				}
				mu.Lock()
				cs.Entries = append(cs.Entries, corpusEntry{URL: abs, File: name, Status: r.StatusCode, ContentType: r.Header.Get("Content-Type")})
				mu.Unlock()
			}(abs, a.typ)
		}
		wg.Wait()
		sort.Slice(cs.Entries, func(i, j int) bool { return cs.Entries[i].URL < cs.Entries[j].URL })
		manifest, _ := json.MarshalIndent(cs, "", "  ")
		if err := os.WriteFile(filepath.Join(sdir, "manifest.json"), manifest, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: html=%dB assets=%d", site, len(body), len(cs.Entries))
	}
}

type loadedSite struct {
	corpusSite
	body  []byte
	files map[string]corpusEntry
	data  map[string][]byte
}

func loadCorpus(tb testing.TB) []*loadedSite {
	dir := corpusDir(tb)
	var sites []*loadedSite
	for _, site := range sitesOfCorpus() {
		sdir := filepath.Join(dir, siteDirName(site))
		raw, err := os.ReadFile(filepath.Join(sdir, "manifest.json"))
		if err != nil {
			tb.Fatalf("%s: %v (run TestCorpusFetch first)", site, err)
		}
		ls := &loadedSite{files: map[string]corpusEntry{}, data: map[string][]byte{}}
		if err := json.Unmarshal(raw, &ls.corpusSite); err != nil {
			tb.Fatal(err)
		}
		ls.body, err = os.ReadFile(filepath.Join(sdir, ls.Body))
		if err != nil {
			tb.Fatal(err)
		}
		for _, e := range ls.Entries {
			ls.files[e.URL] = e
			ls.data[e.URL], err = os.ReadFile(filepath.Join(sdir, e.File))
			if err != nil {
				tb.Fatal(err)
			}
		}
		sites = append(sites, ls)
	}
	return sites
}

// corpusTransport serves every request from the loaded corpus.
type corpusTransport struct{ sites []*loadedSite }

func (c corpusTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		req.Body.Close()
	}
	u := req.URL.String()
	for _, s := range c.sites {
		if e, ok := s.files[u]; ok {
			h := http.Header{}
			h.Set("Content-Type", e.ContentType)
			return &http.Response{StatusCode: e.Status, Header: h, Body: io.NopCloser(bytes.NewReader(s.data[u])), Request: req}, nil
		}
	}
	return &http.Response{StatusCode: 404, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
}

// withOfflineCorpus routes default-transport HTTP to the corpus and disables
// DNS queries for the duration of the test.
func withOfflineCorpus(tb testing.TB, sites []*loadedSite) {
	oldTransport, oldDNS := http.DefaultTransport, DNSRecordTypes
	http.DefaultTransport = corpusTransport{sites}
	DNSRecordTypes = nil
	tb.Cleanup(func() {
		http.DefaultTransport, DNSRecordTypes = oldTransport, oldDNS
	})
}

func sortedTechs(m map[string]AppInfo) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestCorpusDetections prints the detected technologies per site so results
// can be diffed across changes. Set KITSUNE_CORPUS_OUT to write them to a file.
func TestCorpusDetections(t *testing.T) {
	sites := loadCorpus(t)
	withOfflineCorpus(t, sites)
	engine, err := New()
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	for _, s := range sites {
		var ms runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&ms)
		before := ms.TotalAlloc
		start := time.Now()
		res := engine.FingerprintWithInfoAndURL(s.Headers, s.body, s.URL)
		elapsed := time.Since(start)
		runtime.ReadMemStats(&ms)
		techs := sortedTechs(res)
		t.Logf("%-28s %6dms %7.1fMB alloc  %d techs", s.URL, elapsed.Milliseconds(), float64(ms.TotalAlloc-before)/(1<<20), len(techs))
		fmt.Fprintf(&out, "%s\n", s.URL)
		for _, tech := range techs {
			fmt.Fprintf(&out, "  %s\n", tech)
		}
	}
	if p := os.Getenv("KITSUNE_CORPUS_OUT"); p != "" {
		if err := os.WriteFile(p, []byte(out.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	} else {
		t.Log("\n" + out.String())
	}
}

func BenchmarkCorpus(b *testing.B) {
	sites := loadCorpus(b)
	withOfflineCorpus(b, sites)
	engine, err := New()
	if err != nil {
		b.Fatal(err)
	}
	for _, s := range sites {
		b.Run(siteDirName(s.URL), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				engine.FingerprintWithInfoAndURL(s.Headers, s.body, s.URL)
			}
		})
	}
}
