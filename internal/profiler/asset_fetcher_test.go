package profiler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
)

// failingReader returns its data and then an error, as a body cut by a
// timeout does.
type failingReader struct{ r io.Reader }

func (f *failingReader) Read(p []byte) (int, error) {
	n, err := f.r.Read(p)
	if err == io.EOF {
		return n, errors.New("timeout")
	}
	return n, err
}

func TestReadString(t *testing.T) {
	body := strings.Repeat("abcdefghij", 1000) // 10000 bytes
	tests := []struct {
		name          string
		contentLength int64
		limit, budget int64
		failing       bool
		want          int
		wantErr       bool
	}{
		{"unknown length", -1, 1 << 20, 1 << 20, false, 10000, false},
		{"known length", 10000, 1 << 20, 1 << 20, false, 10000, false},
		{"limit", -1, 4000, 1 << 20, false, 4000, false},
		{"budget", 10000, 1 << 20, 3000, false, 3000, false},
		{"no budget", 10000, 1 << 20, 0, false, 0, false},
		{"error keeps what was read", -1, 1 << 20, 1 << 20, true, 10000, true},
	}
	for _, tt := range tests {
		var r io.Reader = strings.NewReader(body)
		if tt.failing {
			r = &failingReader{r}
		}
		resp := &http.Response{Body: io.NopCloser(r), ContentLength: tt.contentLength}
		var budget atomic.Int64
		budget.Store(tt.budget)
		got, err := readString(resp, tt.limit, &budget)
		if len(got) != tt.want || got != body[:len(got)] || (err != nil) != tt.wantErr {
			t.Errorf("%s: read %d bytes, err %v; want %d, err %v", tt.name, len(got), err, tt.want, tt.wantErr)
		}
		if left := budget.Load(); left != tt.budget-int64(len(got)) {
			t.Errorf("%s: budget left %d, want %d", tt.name, left, tt.budget-int64(len(got)))
		}
	}
}

func TestAssetFetcherCaps(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if strings.HasSuffix(r.URL.Path, ".css") {
			w.Header().Set("Content-Type", "text/css")
		} else {
			w.Header().Set("Content-Type", "application/javascript")
		}
		io.WriteString(w, "x")
	}))
	defer srv.Close()

	var wg sync.WaitGroup
	var mu sync.Mutex
	got := map[string]int{}
	af := NewAssetFetcher(srv.URL+"/", context.Background(), &wg, 10, func(assetType, _ string) {
		mu.Lock()
		got[assetType]++
		mu.Unlock()
	})
	af.Start()
	for i := 0; i < 1000; i++ {
		af.AddURL(fmt.Sprintf("%s/%d.js", srv.URL, i), "script", 0)
		af.AddURL(fmt.Sprintf("%s/%d.css", srv.URL, i), "style", 0)
		af.AddURL(srv.URL+"/0.js", "script", 0) // a repeat counts once
	}
	af.Stop()
	wg.Wait()
	if got["script"] != maxScripts || got["style"] != maxStyles || hits.Load() != maxScripts+maxStyles {
		t.Errorf("fetched %d scripts, %d styles in %d requests; want %d, %d", got["script"], got["style"], hits.Load(), maxScripts, maxStyles)
	}
}

func TestScriptPreloads(t *testing.T) {
	body := `<html><head>
<link rel="modulepreload" href="a.js">
<link rel="ModulePreload" as="script" href="/b.js">
<link rel="modulepreload" as="style" href="not-a-script.js">
<link rel="preload" as="script" href="https://cdn.example.com/c.js">
<link rel="preload prefetch" as="SCRIPT" href="../d.js">
<link rel="preload" as="style" href="e.css">
<link rel="preload" href="f.js">
<link rel="prefetch" as="script" href="g.js">
<link rel="stylesheet" href="h.css">
<link rel="modulepreload" href="data:text/javascript,1">
</head></html>`
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	base, _ := url.Parse("https://www.example.com/app/page")
	got := scriptPreloads(doc, base)
	want := []string{
		"https://www.example.com/app/a.js",
		"https://www.example.com/b.js",
		"https://cdn.example.com/c.js",
		"https://www.example.com/d.js",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSelectPreloads(t *testing.T) {
	urls := []string{
		"https://x.com/assets/BxQ3a1.js",
		"https://x.com/assets/vendor-3f2a.js",
		"https://x.com/assets/route-about.js",
		"https://x.com/_next/static/chunks/framework-9a.js?v=1",
		"https://x.com/assets/Dk9q.js",
		"https://x.com/react/route.js", // only the file name counts
		"https://x.com/assets/index-Cd3.js",
	}
	want := []string{
		"https://x.com/assets/vendor-3f2a.js",
		"https://x.com/_next/static/chunks/framework-9a.js?v=1",
		"https://x.com/assets/index-Cd3.js",
		"https://x.com/assets/BxQ3a1.js",
	}
	if got := selectPreloads(urls, 4); !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := selectPreloads(urls, 10); !reflect.DeepEqual(got, urls) {
		t.Errorf("under the cap: got %q, want all in order", got)
	}
}

// TestAssetFetcherPreloadsWait checks that preloads don't take fetch slots
// while the page's own scripts wait for one.
func TestAssetFetcherPreloadsWait(t *testing.T) {
	gate := make(chan struct{})
	var scripts, preloads atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		if strings.HasPrefix(r.URL.Path, "/preload") {
			preloads.Add(1)
			return
		}
		scripts.Add(1)
		<-gate
	}))
	defer srv.Close()

	var wg sync.WaitGroup
	af := NewAssetFetcher(srv.URL+"/", context.Background(), &wg, 10, func(string, string) {})
	af.Start()
	for i := 0; i < 25; i++ {
		af.AddURL(fmt.Sprintf("%s/script%d.js", srv.URL, i), "script", 5)
	}
	var urls []string
	for i := 0; i < 50; i++ {
		urls = append(urls, fmt.Sprintf("%s/preload%d.js", srv.URL, i))
	}
	af.AddPreloads(urls)
	af.Stop()
	for scripts.Load() < 10 {
		time.Sleep(time.Millisecond)
	}
	// All slots are taken by scripts, and 15 more wait for one.
	time.Sleep(50 * time.Millisecond)
	if n := preloads.Load(); n != 0 {
		t.Errorf("%d preloads fetched while scripts waited", n)
	}
	close(gate)
	wg.Wait()
	if scripts.Load() != 25 || preloads.Load() != maxPreloads {
		t.Errorf("fetched %d scripts, %d preloads; want 25, %d", scripts.Load(), preloads.Load(), maxPreloads)
	}
}

func TestPreloadPipeline(t *testing.T) {
	w := testEngine(t, map[string]*Fingerprint{
		"Page":   {Script: []string{`page-script-code`}},
		"Vendor": {Script: []string{`bundled-vendor-code`}},
	}, nil)
	// Assets go to the test server.
	http.DefaultTransport = &http.Transport{}
	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/javascript")
		switch {
		case strings.HasPrefix(r.URL.Path, "/page"):
			io.WriteString(w, "page-script-code")
		case strings.HasPrefix(r.URL.Path, "/assets/vendor"):
			io.WriteString(w, "bundled-vendor-code")
		}
	}))
	defer srv.Close()

	var b strings.Builder
	b.WriteString("<html><head>\n")
	// Many preloads before the scripts, the vendor chunk past the cap in
	// document order, and a script that is also preloaded.
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&b, "<link rel=modulepreload href=/assets/C%02dx.js>\n", i)
	}
	b.WriteString("<link rel=modulepreload href=/assets/vendor-Ab1.js>\n")
	b.WriteString("<link rel=preload as=script href=/page0.js>\n")
	for i := 0; i < 3; i++ {
		fmt.Fprintf(&b, "<script src=/page%d.js></script>\n", i)
	}
	b.WriteString("</head></html>")

	got := w.FingerprintWithURL(nil, []byte(b.String()), srv.URL+"/")
	checkTechs(t, "page", got, "Page", "Vendor")
	var pages, preloads int
	for path, n := range hits {
		if n != 1 {
			t.Errorf("%s fetched %d times", path, n)
		}
		if strings.HasPrefix(path, "/page") {
			pages++
		} else {
			preloads++
		}
	}
	if pages != 3 || preloads != maxPreloads {
		t.Errorf("fetched %d scripts, %d preloads; want 3, %d", pages, preloads, maxPreloads)
	}
}
