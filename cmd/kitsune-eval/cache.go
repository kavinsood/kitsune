package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// The cache holds a snapshot of the pages of both sets:
//
//	snapshot.json        when the snapshot was taken (see snapshot)
//	corpus/<host>.json   corpus pages (page)
//	truth/<id>.json      truth pages, with their DNS records
//	assets/index.json    scripts, stylesheets and containers the truth pages
//	assets/<hash>        load, by URL (assetEntry), and their content
//	results/<tag>.json   saved results (results)
//
// Page files are the JSON records cmd/update-fingerprints -corpus reads.

// snapshot describes when and how the pages of a cache were taken.
type snapshot struct {
	// Created is when the first pages were taken, Updated when pages were
	// last added.
	Created time.Time `json:"created"`
	Updated time.Time `json:"updated"`
	Source  string    `json:"source"`
}

// page is a saved response to a GET of URL, after redirects to Final.
type page struct {
	URL     string
	Final   string
	Status  int
	Headers map[string][]string
	Body    []byte
	Fetched time.Time
	// DNS holds the records of Final's host, keyed by type, and Recorded
	// says they and the page's assets have been saved (truth pages).
	DNS      map[string][]string `json:",omitempty"`
	Recorded bool                `json:",omitempty"`
}

type cache struct {
	dir    string
	snap   snapshot
	assets *assetStore
}

func openCache(dir string) (*cache, error) {
	c := &cache{dir: dir}
	for _, d := range []string{"corpus", "truth", "assets", "results"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			return nil, err
		}
	}
	if err := readJSON(filepath.Join(dir, "snapshot.json"), &c.snap); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	c.assets = &assetStore{dir: filepath.Join(dir, "assets"), index: map[string]assetEntry{}}
	if err := readJSON(filepath.Join(c.assets.dir, "index.json"), &c.assets.index); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	return c, nil
}

// clear removes the snapshot, keeping saved results.
func (c *cache) clear() error {
	for _, d := range []string{"corpus", "truth", "assets"} {
		if err := os.RemoveAll(filepath.Join(c.dir, d)); err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Join(c.dir, d), 0o755); err != nil {
			return err
		}
	}
	c.snap = snapshot{}
	c.assets.index = map[string]assetEntry{}
	return os.RemoveAll(filepath.Join(c.dir, "snapshot.json"))
}

func (c *cache) saveSnapshot() error {
	return writeJSON(filepath.Join(c.dir, "snapshot.json"), c.snap)
}

// describe says where the snapshot is and when it was taken.
func (c *cache) describe() string {
	if c.snap.Created.IsZero() {
		return fmt.Sprintf("snapshot %s: empty", c.dir)
	}
	return fmt.Sprintf("snapshot %s:\n  %s", c.dir, describeSnapshot(c.snap))
}

func describeSnapshot(s snapshot) string {
	const layout = "2006-01-02 15:04 MST"
	days := int(time.Since(s.Created).Hours() / 24)
	d := fmt.Sprintf("taken %s (%d days ago)", s.Created.UTC().Format(layout), days)
	if s.Updated.Sub(s.Created) > time.Hour {
		d += fmt.Sprintf(", pages added %s", s.Updated.UTC().Format(layout))
	}
	d += ", " + s.Source
	if days > 30 {
		d += "\n  The sites have likely changed since: a lower score may be drift, not a regression (see README.md)."
	}
	return d
}

func (c *cache) pagePath(set, name string) string {
	return filepath.Join(c.dir, set, name+".json")
}

// loadPage returns the saved page, or nil if there is none.
func (c *cache) loadPage(set, name string) (*page, error) {
	var p page
	if err := readJSON(c.pagePath(set, name), &p); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return &p, nil
}

func (c *cache) savePage(set, name string, p *page) error {
	return writeJSON(c.pagePath(set, name), p)
}

func (c *cache) resultsDir() string { return filepath.Join(c.dir, "results") }

func (c *cache) saveResults(r *results) error {
	if r.Tag == "" || strings.ContainsAny(r.Tag, `/\`) {
		return fmt.Errorf("invalid tag %q", r.Tag)
	}
	return writeJSON(filepath.Join(c.resultsDir(), r.Tag+".json"), r)
}

// loadResults loads the results saved as tag, or from the file tag if it
// ends in .json (results of another cache, say).
func (c *cache) loadResults(tag string) (*results, error) {
	path := filepath.Join(c.resultsDir(), tag+".json")
	if strings.HasSuffix(tag, ".json") {
		path = tag
	}
	var r results
	if err := readJSON(path, &r); err != nil {
		return nil, fmt.Errorf("results %q: %w", tag, err)
	}
	return &r, nil
}

// assetEntry is a saved response to a GET of an asset's URL, after
// redirects.
type assetEntry struct {
	File        string `json:"file"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
}

// assetStore holds the assets of a cache, by URL.
type assetStore struct {
	dir   string
	mu    sync.Mutex
	index map[string]assetEntry
}

func (s *assetStore) get(url string) (assetEntry, []byte, bool) {
	s.mu.Lock()
	e, ok := s.index[url]
	s.mu.Unlock()
	if !ok {
		return e, nil, false
	}
	data, err := os.ReadFile(filepath.Join(s.dir, e.File))
	if err != nil {
		return e, nil, false
	}
	return e, data, true
}

func (s *assetStore) put(url string, status int, contentType string, data []byte) error {
	h := sha1.Sum([]byte(url))
	e := assetEntry{File: hex.EncodeToString(h[:8]), Status: status, ContentType: contentType}
	if err := os.WriteFile(filepath.Join(s.dir, e.File), data, 0o644); err != nil {
		return err
	}
	s.mu.Lock()
	s.index[url] = e
	s.mu.Unlock()
	return nil
}

func (s *assetStore) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.index)
}

func (s *assetStore) save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeJSON(filepath.Join(s.dir, "index.json"), s.index)
}

// response returns e as the response to req.
func (e assetEntry) response(req *http.Request, data []byte) *http.Response {
	h := http.Header{}
	if e.ContentType != "" {
		h.Set("Content-Type", e.ContentType)
	}
	return &http.Response{
		Status:        fmt.Sprintf("%d %s", e.Status, http.StatusText(e.Status)),
		StatusCode:    e.Status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        h,
		Body:          io.NopCloser(bytes.NewReader(data)),
		ContentLength: int64(len(data)),
		Request:       req,
	}
}

// replayTransport serves requests from the assets of a cache, and those
// it doesn't have as 404s, which it lists in missed.
type replayTransport struct {
	store  *assetStore
	mu     sync.Mutex
	missed map[string]bool
}

func (t *replayTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		req.Body.Close()
	}
	u := req.URL.String()
	if e, data, ok := t.store.get(u); ok {
		return e.response(req, data), nil
	}
	t.mu.Lock()
	t.missed[u] = true
	t.mu.Unlock()
	return assetEntry{Status: http.StatusNotFound}.response(req, nil), nil
}

func (t *replayTransport) missedURLs() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	urls := make([]string, 0, len(t.missed))
	for u := range t.missed {
		urls = append(urls, u)
	}
	sort.Strings(urls)
	return urls
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}
