package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kavinsood/kitsune/internal/profiler"
)

const (
	// userAgent is the one internal/api fetches pages with.
	userAgent = "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5931.0 Safari/537.36"
	// maxPageBytes is how much of a page is read, as in internal/api.
	maxPageBytes = 5 << 20
	// maxAssetBytes is how much of an asset is saved: more than the
	// profiler reads, so that a build reading more can be evaluated.
	maxAssetBytes = 4 << 20
	// recordPasses bounds how many times a truth page is analyzed to
	// record its assets (see recordPage).
	recordPasses = 4
)

// lookupDNS queries DNS; runs replace profiler.LookupDNS.
var lookupDNS = profiler.LookupDNS

// complete downloads the pages missing from the cache, records the DNS
// records of those that don't have them, and records the assets the
// engine now fetches that the cache doesn't have: recorded pages are
// analyzed again, as an engine change can fetch more of their assets.
// Assets already recorded are served from the cache, not downloaded.
func (c *cache) complete(engine *profiler.Wappalyze, l *labels) error {
	type job struct {
		set, name, url string
		p              *page
	}
	var jobs []*job
	add := func(set, name, url string) error {
		p, err := c.loadPage(set, name)
		if err != nil {
			return err
		}
		jobs = append(jobs, &job{set: set, name: name, url: url, p: p})
		return nil
	}
	for _, s := range l.corpus {
		if err := add("corpus", s.Host, "https://"+s.Host+"/"); err != nil {
			return err
		}
	}
	for _, s := range l.truth {
		if err := add("truth", s.ID, s.URL); err != nil {
			return err
		}
	}
	if len(jobs) == 0 {
		return nil
	}

	var mu sync.Mutex
	failed := 0
	fail := func(j *job, err error) {
		mu.Lock()
		failed++
		mu.Unlock()
		fmt.Fprintf(os.Stderr, "  %s %s: %v\n", j.set, j.name, err)
	}
	var fetch []*job
	for _, j := range jobs {
		if j.p == nil {
			fetch = append(fetch, j)
		}
	}
	if len(fetch) > 0 {
		fmt.Fprintf(os.Stderr, "downloading %d pages into %s\n", len(fetch), c.dir)
		client := &http.Client{Transport: realTransport, Timeout: 20 * time.Second}
		parallel(fetch, 8, func(j *job) {
			p, err := fetchPage(client, j.url)
			if err != nil {
				fail(j, err)
				return
			}
			if j.set == "corpus" {
				p.URL = j.name // as in the corpus records of update-fingerprints
			}
			if err := c.savePage(j.set, j.name, p); err != nil {
				fail(j, err)
				return
			}
			j.p = p
		})
	}

	rec := &recorder{
		store:    c.assets,
		client:   &http.Client{Transport: realTransport, Timeout: 30 * time.Second},
		inflight: map[string]chan struct{}{},
	}
	oldTransport, oldDNS := http.DefaultTransport, profiler.LookupDNS
	http.DefaultTransport = rec
	// Assets don't depend on DNS; don't query it on every pass.
	profiler.LookupDNS = func(string) map[string][]string { return nil }
	parallel(jobs, 4, func(j *job) {
		if j.p == nil {
			return // not downloaded
		}
		if err := recordPage(engine, rec, j.set, j.p); err != nil {
			fail(j, err)
			return
		}
		if err := c.savePage(j.set, j.name, j.p); err != nil {
			fail(j, err)
		}
	})
	http.DefaultTransport, profiler.LookupDNS = oldTransport, oldDNS
	if len(fetch) == 0 && rec.recorded() == 0 && failed == 0 {
		return nil
	}
	fmt.Fprintf(os.Stderr, "recorded %d new assets\n", rec.recorded())
	if err := c.assets.save(); err != nil {
		return err
	}

	now := time.Now().UTC().Truncate(time.Second)
	if c.snap.Created.IsZero() {
		c.snap.Created = now
		c.snap.Source = "downloaded from the live sites"
	}
	c.snap.Updated = now
	if err := c.saveSnapshot(); err != nil {
		return err
	}
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "%d pages failed; they are retried on the next run\n", failed)
	}
	return nil
}

// analyze returns the techs detected on p, a page of set, as the evals
// analyze it: corpus pages without their URL, so without DNS and with only
// the assets they link by absolute URL; truth pages at their final URL, as
// internal/api does. Truth pages not served with status 200 aren't
// analyzed (ok is false).
func analyze(engine *profiler.Wappalyze, set string, p *page) (techs map[string]struct{}, ok bool) {
	if set == "corpus" {
		return engine.Fingerprint(p.Headers, p.Body), true
	}
	if p.Status != http.StatusOK {
		return nil, false
	}
	return engine.FingerprintWithURL(p.Headers, p.Body, p.Final), true
}

// fetchPage GETs rawURL as internal/api does.
func fetchPage(client *http.Client, rawURL string) (*page, error) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPageBytes))
	if err != nil {
		return nil, err
	}
	return &page{
		URL:     rawURL,
		Final:   resp.Request.URL.String(),
		Status:  resp.StatusCode,
		Headers: resp.Header,
		Body:    body,
		Fetched: time.Now().UTC().Truncate(time.Second),
	}, nil
}

// recordPage saves the DNS records of p's host into p (truth pages not
// yet recorded), and
// the assets its analysis fetches into rec's store. Assets are recorded in
// full even if the analysis gives up on them, and those it didn't get to
// before its timeout are fetched by the next analysis, which gets the
// recorded ones at once, until a pass adds none.
func recordPage(engine *profiler.Wappalyze, rec *recorder, set string, p *page) error {
	if set == "truth" && !p.Recorded {
		u, err := url.Parse(p.Final)
		if err != nil {
			return err
		}
		p.DNS = lookupDNS(u.Hostname())
	}
	for range recordPasses {
		before := rec.recorded()
		if _, ok := analyze(engine, set, p); !ok {
			break
		}
		rec.wait()
		if rec.recorded() == before {
			break
		}
	}
	p.Recorded = true
	return nil
}

// recorder is a transport that serves requests from an asset store,
// first downloading into it those it doesn't have.
type recorder struct {
	store    *assetStore
	client   *http.Client
	mu       sync.Mutex
	inflight map[string]chan struct{}
	count    int // assets recorded, guarded by mu
	wg       sync.WaitGroup
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		req.Body.Close()
	}
	u := req.URL.String()
	r.mu.Lock()
	done, ok := r.inflight[u]
	if !ok {
		if e, data, ok := r.store.get(u); ok {
			r.mu.Unlock()
			return e.response(req, data), nil
		}
		done = make(chan struct{})
		r.inflight[u] = done
		r.wg.Add(1)
		go r.record(u, req.Header.Clone(), done)
	}
	r.mu.Unlock()
	select {
	case <-done:
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
	if e, data, ok := r.store.get(u); ok {
		return e.response(req, data), nil
	}
	return nil, fmt.Errorf("couldn't record %s", u)
}

// record downloads u into the store, independently of the request for it.
func (r *recorder) record(u string, header http.Header, done chan struct{}) {
	defer r.wg.Done()
	defer close(done)
	ok := false
	defer func() {
		r.mu.Lock()
		delete(r.inflight, u)
		if ok {
			r.count++
		}
		r.mu.Unlock()
	}()
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return
	}
	req.Header = header
	resp, err := r.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAssetBytes))
	if err != nil && len(data) == 0 {
		return
	}
	ok = r.store.put(u, resp.StatusCode, resp.Header.Get("Content-Type"), data) == nil
}

func (r *recorder) recorded() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}

func (r *recorder) wait() { r.wg.Wait() }

// importPages starts the cache from pages saved by the scripts that
// preceded this command: corpus pages as JSON records named by host, and
// truth pages saved by curl as NN.meta ("status final-url"), NN.hdr (the
// headers of each response of the redirect chain) and NN.html. Their DNS
// records and assets weren't saved, so they are recorded afterwards.
func (c *cache) importPages(l *labels, corpusDir, truthDir string) error {
	if !c.snap.Created.IsZero() {
		return fmt.Errorf("%s already has a snapshot; import into a new -cache", c.dir)
	}
	if corpusDir == "" && truthDir == "" {
		return fmt.Errorf("nothing to import: use -corpus and -truth")
	}
	var oldest time.Time
	saved := func(set, name string, p *page) error {
		if oldest.IsZero() || p.Fetched.Before(oldest) {
			oldest = p.Fetched
		}
		return c.savePage(set, name, p)
	}
	var from []string
	if corpusDir != "" {
		n := 0
		for _, s := range l.corpus {
			file := filepath.Join(corpusDir, s.Host+".json")
			var p page
			if err := readJSON(file, &p); err != nil {
				fmt.Fprintf(os.Stderr, "  corpus %s: %v\n", s.Host, err)
				continue
			}
			p.Fetched = fetchedAt(p.Headers, file)
			if err := saved("corpus", s.Host, &p); err != nil {
				return err
			}
			n++
		}
		from = append(from, fmt.Sprintf("%d corpus pages from %s", n, corpusDir))
	}
	if truthDir != "" {
		n := 0
		for _, s := range l.truth {
			p, responses, err := readCurlPage(filepath.Join(truthDir, s.ID))
			if err != nil {
				fmt.Fprintf(os.Stderr, "  truth %s: %v\n", s.ID, err)
				continue
			}
			p.URL = s.URL
			// A page saved again over an older one may keep the older .meta:
			// without a redirect, it was fetched from the labeled URL.
			if responses == 1 && hostOf(p.Final) != hostOf(s.URL) {
				fmt.Fprintf(os.Stderr, "  truth %s: .meta names %s but the page was not redirected; using %s\n", s.ID, p.Final, s.URL)
				p.Final = s.URL
			}
			if err := saved("truth", s.ID, p); err != nil {
				return err
			}
			n++
		}
		from = append(from, fmt.Sprintf("%d truth pages from %s", n, truthDir))
	}
	c.snap = snapshot{
		Created: oldest,
		Updated: oldest,
		Source:  "imported " + strings.Join(from, " and ") + "; their assets and DNS records downloaded on import",
	}
	return c.saveSnapshot()
}

// readCurlPage reads the page saved as base+".meta", ".hdr" and ".html", and
// says how many responses .hdr holds: more than one if it was redirected.
func readCurlPage(base string) (*page, int, error) {
	meta, err := os.ReadFile(base + ".meta")
	if err != nil {
		return nil, 0, err
	}
	f := strings.Fields(string(meta))
	if len(f) < 2 {
		return nil, 0, fmt.Errorf("%s.meta: want \"status url\"", base)
	}
	status, err := strconv.Atoi(f[0])
	if err != nil {
		return nil, 0, fmt.Errorf("%s.meta: %v", base, err)
	}
	body, err := os.ReadFile(base + ".html")
	if err != nil {
		return nil, 0, err
	}
	hdr, err := os.ReadFile(base + ".hdr")
	if err != nil {
		return nil, 0, err
	}
	headers := map[string][]string{}
	responses := 0
	sc := bufio.NewScanner(bytes.NewReader(hdr))
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.HasPrefix(line, "HTTP/") {
			headers = map[string][]string{} // keep the last response of the redirect chain
			responses++
			continue
		}
		if k, v, ok := strings.Cut(line, ":"); ok {
			headers[k] = append(headers[k], strings.TrimSpace(v))
		}
	}
	return &page{
		Final:   f[1],
		Status:  status,
		Headers: headers,
		Body:    body,
		Fetched: fetchedAt(headers, base+".html"),
	}, responses, nil
}

// hostOf returns the host of rawURL, or "" if it doesn't parse.
func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// fetchedAt returns when a saved response was received: the modification
// time of its file, or else its Date header (which a CDN may have cached).
func fetchedAt(headers map[string][]string, file string) time.Time {
	if st, err := os.Stat(file); err == nil {
		return st.ModTime().UTC().Truncate(time.Second)
	}
	for k, v := range headers {
		if strings.EqualFold(k, "Date") && len(v) > 0 {
			if t, err := http.ParseTime(v[0]); err == nil {
				return t.UTC()
			}
		}
	}
	return time.Time{}
}

// parallel calls f on each job, n at a time.
func parallel[T any](jobs []T, n int, f func(T)) {
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	for _, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			f(j)
		}()
	}
	wg.Wait()
}
