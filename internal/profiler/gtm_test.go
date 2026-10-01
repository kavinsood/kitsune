package profiler

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeContainer is a GTM container: its configuration, then a runtime that
// mentions things no tag of the container loads.
const fakeContainerData = `
// Copyright 2012 Google Inc. All rights reserved.
(function(){
var data = {
"resource": {
  "version": "7",
  "macros": [
    {"function": "__c", "vtp_value": "G-ABC1234567"},
    {"function": "__v", "vtp_name": "id", "vtp_default": ["macro", 0]},
    {"function": "__c", "vtp_value": "AW-123456789"}
  ],
  "tags": [
    {"function": "__googtag", "tag_id": 1, "vtp_tagId": ["macro", 1]},
    {"function": "__paused", "vtp_originalTagType": "hjtc", "tag_id": 2},
    {"function": "__bzi", "vtp_id": "123", "tag_id": 3},
    {"function": "__baut", "tag_id": 4, "setup_tags": ["list", ["tag", 4, 0]]},
    {"function": "__html", "tag_id": 5, "vtp_html": ["template", "<script>fbq('init','1');</script><img src=\"https://pixel.example.com/p?x=", ["escape", ["macro", 0], 8, 16], "\">"]},
    {"function": "__pntr", "tag_id": 6},
    {"function": "__cvt_1", "tag_id": 7, "vtp_conversionId": ["macro", 2]}
  ],
  "predicates": [{"function": "_eq", "arg0": ["macro", 1], "arg1": "gtm.js"}],
  "rules": [[["if", 0], ["add", 0, 1, 3, 5, 6]]]
},
"runtime": [],
"permissions": {
  "__baut": {"inject_script": {"urls": ["https://bat.bing.com/bat.js"]}},
  "__bzi": {"inject_script": {"urls": ["https://snap.licdn.com/*"]}},
  "__cvt_1": {"inject_script": {"urls": ["https://capi.s3.us-east-2.amazonaws.com/x.js", "https://*.example.org/*"]}}
}
};`

const fakeContainerRuntime = `
var f = "/wp-content/"; var g = "gtm:tag __hjtc id:G-ZZZZZZZZ"; // runtime
})();`

var gtmTestApps = map[string]*Fingerprint{
	"GA":        {Script: []string{`gtm:tag __googtag [^\n]*id:G-[A-Z0-9]{6,}`}},
	"Ads":       {Script: []string{`gtm:tag __cvt_1 [^\n]*id:AW-\d{6,}`}},
	"Hotjar":    {Script: []string{`gtm:tag __hjtc `}},
	"LinkedIn":  {Script: []string{`gtm:tag __bzi `}, ScriptSrc: []string{`snap\.licdn\.com`}},
	"Bing":      {ScriptSrc: []string{`bat\.bing\.com/bat\.js`}},
	"Pinterest": {Script: []string{`gtm:tag __pntr `}},
	"Pixel":     {Script: []string{`fbq\('init'`}},
	"Custom":    {HTML: []string{`<img[^>]+pixel\.example\.com`}},
	"S3":        {Cats: []int{31}, ScriptSrc: []string{`\.s3\.[^/]*amazonaws\.com`}},
	"WordPress": {Script: []string{`/wp-content/`}},
	"Gtag":      {Script: []string{`gtm:tag __ogt_ga `}},
}

func TestGTMContainerIDs(t *testing.T) {
	body := `<script>(function(w,d,s,l,i){})(window,document,'script','dataLayer','GTM-AAAA1');</script>
<noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-BBBB2&gtm_auth=x"></iframe></noscript>
<p>We moved off GTM-PROSE1 last year, and GTM-AB is too short.</p>
<div data-gtm-container-id="GTM-CCCC3"></div>
<script>self.__next_f.push([1,"{\"gtmId\":\"GTM-ESC4\"}"])</script>
<script>gtm('GTM-AAAA1'); x = "GTM-MISMATCH'</script>`
	got := gtmContainerIDs([]byte(body), 8)
	want := []string{"GTM-AAAA1", "GTM-BBBB2", "GTM-CCCC3", "GTM-ESC4"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ids: got %q, want %q", got, want)
	}
	if got := gtmContainerIDs([]byte(body), 2); !reflect.DeepEqual(got, want[:2]) {
		t.Errorf("capped ids: got %q, want %q", got, want[:2])
	}
}

func TestGoogleTagKey(t *testing.T) {
	for url, want := range map[string]string{
		"https://www.googletagmanager.com/gtm.js?id=GTM-AAAA1":     "gtm.js?id=GTM-AAAA1",
		"https://www.googletagmanager.com/gtag/js?id=G-ABC123&l=x": "gtag/js?id=G-ABC123",
		"https://www.googletagmanager.com/gtm.js":                  "",
		"https://www.googletagmanager.com/ns.html?id=GTM-AAAA1":    "",
		"https://cdn.example.com/gtm.js?id=GTM-AAAA1":              "",
	} {
		if got := googleTagKey(url); got != want {
			t.Errorf("googleTagKey(%q) = %q, want %q", url, got, want)
		}
	}
}

// errAfterData fails reads past the configuration.
var errAfterData = errors.New("read past the container data")

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errAfterData }

func TestReadGTMContainer(t *testing.T) {
	c, err := readGTMContainer(io.MultiReader(strings.NewReader(fakeContainerData), failingReader{}))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	ev := c.evidence()
	// The paused tag and the tag no rule adds are left out; the tag set up
	// by a live tag is in. Variables are followed to the ids.
	wantTags := "gtm:tag __googtag id:G-ABC1234567 \n" +
		"gtm:tag __baut \n" +
		"gtm:tag __html \n" +
		"gtm:tag __pntr \n" +
		"gtm:tag __cvt_1 id:AW-123456789 \n"
	if ev.tags != wantTags {
		t.Errorf("tags: got\n%s\nwant\n%s", ev.tags, wantTags)
	}
	wantSrcs := []string{"https://bat.bing.com/bat.js", "https://capi.s3.us-east-2.amazonaws.com/x.js"}
	if !reflect.DeepEqual(ev.scriptSrcs, wantSrcs) {
		t.Errorf("script srcs: got %q, want %q", ev.scriptSrcs, wantSrcs)
	}
	if len(ev.html) != 1 || !strings.Contains(ev.html[0], `<img src="https://pixel.example.com/p?x=">`) {
		t.Errorf("html: got %q", ev.html)
	}
	if !reflect.DeepEqual(ev.inlineScripts, []string{"fbq('init','1');"}) {
		t.Errorf("inline scripts: got %q", ev.inlineScripts)
	}

	if _, err := readGTMContainer(strings.NewReader("var x = 1;")); err == nil {
		t.Error("read a container without data")
	}
}

// gtmServer serves containers at googleTagOrigin for the test, counting
// requests by id.
func gtmServer(t *testing.T, containers map[string]string) (hits func() map[string]int) {
	t.Helper()
	var mu sync.Mutex
	counts := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		mu.Lock()
		counts[r.URL.Path+"?id="+id]++
		mu.Unlock()
		body, ok := containers[id]
		if !ok || r.URL.Path != "/gtm.js" && r.URL.Path != "/gtag/js" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/javascript; charset=UTF-8")
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	old := googleTagOrigin
	googleTagOrigin = srv.URL
	t.Cleanup(func() { googleTagOrigin = old })
	return func() map[string]int {
		mu.Lock()
		defer mu.Unlock()
		out := map[string]int{}
		for k, v := range counts {
			out[k] = v
		}
		return out
	}
}

func TestGTMPipeline(t *testing.T) {
	w := testEngine(t, gtmTestApps, nil)
	// Assets go to the test server.
	http.DefaultTransport = &http.Transport{}
	gtag := `var data = {"resource": {"macros": [], "tags": [{"function": "__ogt_ga", "vtp_id": "G-XYZ12345"}], "rules": [[["add", 0]]]}};` + fakeContainerRuntime
	hits := gtmServer(t, map[string]string{
		"GTM-AAAA1":  fakeContainerData + fakeContainerRuntime,
		"GTM-BBBB2":  `var data = {"resource": {"tags": [{"function": "__hjtc"}], "rules": [[["add", 0]]]}};`,
		"GTM-CCCC3":  `var data = {"resource": {"tags": [{"function": "__bzi"}], "rules": [[["add", 0]]]}};`,
		"G-XYZ12345": gtag,
	})
	body := `<html><head>
<script>(function(w,d,s,l,i){})(window,document,'script','dataLayer','GTM-AAAA1');</script>
<script async src="` + googleTagOrigin + `/gtm.js?id=GTM-AAAA1"></script>
<script async src="` + googleTagOrigin + `/gtag/js?id=G-XYZ12345"></script>
</head><body>
<noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-BBBB2"></iframe></noscript>
<div data-gtm="GTM-CCCC3"></div>
</body></html>`
	got := w.FingerprintWithURL(nil, []byte(body), "https://shop.example.com/")
	// Not WordPress or Hotjar from the runtime, not LinkedIn from an
	// unfired tag, not S3 from a template's permission.
	checkTechs(t, "page", got, "GA", "Ads", "Bing", "Pinterest", "Pixel", "Custom", "Hotjar", "Gtag")
	want := map[string]int{"/gtm.js?id=GTM-AAAA1": 1, "/gtm.js?id=GTM-BBBB2": 1, "/gtag/js?id=G-XYZ12345": 1}
	if h := hits(); !reflect.DeepEqual(h, want) {
		t.Errorf("requests: got %v, want %v", h, want)
	}
}

func TestGTMFetchAfterStop(t *testing.T) {
	gtmServer(t, map[string]string{"GTM-AAAA1": fakeContainerData})
	var wg sync.WaitGroup
	js, css := map[string]string{}, map[string]string{}
	af := NewAssetFetcher("https://shop.example.com/", context.Background(), &wg, 2, &js, &css)
	af.Start()
	af.Stop()
	// Containers don't go through the closed channel, and are counted in
	// wg before they start.
	af.AddGTMContainer("GTM-AAAA1")
	af.AddGTMContainer("GTM-AAAA1")
	wg.Wait()
	if ev := af.GTMEvidence(); len(ev) != 1 || !strings.Contains(ev[0].tags, "__googtag") {
		t.Fatalf("evidence after Wait: %+v", ev)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	af = NewAssetFetcher("https://shop.example.com/", ctx, &wg, 2, &js, &css)
	af.AddGTMContainer("GTM-AAAA1")
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Wait blocked on a container added after the context ended")
	}
	if ev := af.GTMEvidence(); len(ev) != 0 {
		t.Errorf("fetched after the context ended: %+v", ev)
	}
}

// BenchmarkGTMContainers reads and matches saved containers, as fetched
// from googletagmanager.com, in KITSUNE_GTM_CONTAINERS. "generic" matches
// each whole file as a fetched script instead, for comparison.
func BenchmarkGTMContainers(b *testing.B) {
	dir := os.Getenv("KITSUNE_GTM_CONTAINERS")
	if dir == "" {
		b.Skip("KITSUNE_GTM_CONTAINERS not set")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.js"))
	if len(files) == 0 {
		b.Skip("no containers")
	}
	var bodies [][]byte
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			b.Fatal(err)
		}
		bodies = append(bodies, data)
	}
	w, err := New()
	if err != nil {
		b.Fatal(err)
	}
	b.Run("gtm", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for _, data := range bodies {
				c, err := readGTMContainer(bytes.NewReader(data))
				if err != nil {
					b.Fatal(err)
				}
				w.matchGTM(c.evidence(), nil)
			}
		}
	})
	b.Run("generic", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for _, data := range bodies {
				s := string(data)
				w.fingerprints.matchString(s, scriptPart, w.regexTimeout)
				w.fingerprints.matchJSGlobals(s, false)
			}
		}
	})
}
