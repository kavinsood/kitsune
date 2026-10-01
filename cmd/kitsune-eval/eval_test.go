package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/kavinsood/kitsune/internal/profiler"
)

func TestLabels(t *testing.T) {
	l, err := parseLabels(corpusLabels, truthLabels)
	if err != nil {
		t.Fatal(err)
	}
	count := func(n int, techs []string) int { return n + len(techs) }
	var corpusTechs, truthTechs int
	for _, s := range l.corpus {
		corpusTechs = count(corpusTechs, s.Expected)
	}
	for _, s := range l.truth {
		truthTechs = count(truthTechs, s.Expected)
	}
	if len(l.corpus) != 45 || corpusTechs != 53 {
		t.Errorf("corpus: %d sites, %d techs; want 45, 53", len(l.corpus), corpusTechs)
	}
	if len(l.truth) != 37 || truthTechs != 340 {
		t.Errorf("truth: %d sites, %d techs; want 37, 340", len(l.truth), truthTechs)
	}

	// Labels must name techs kitsune has fingerprints for, or they could
	// never be found (or falsely detected).
	engine, err := profiler.New()
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, fp := range engine.GetCompiledFingerprints().Apps {
		known[fp.Name()] = true
	}
	check := func(site string, techs []string) {
		for _, tech := range techs {
			if !known[tech] {
				t.Errorf("%s: unknown tech %q", site, tech)
			}
		}
	}
	hosts, ids := map[string]bool{}, map[string]bool{}
	for _, s := range l.corpus {
		check(s.Host, s.Expected)
		if hosts[s.Host] {
			t.Errorf("corpus: %s listed twice", s.Host)
		}
		hosts[s.Host] = true
	}
	for _, s := range l.truth {
		check(s.ID, s.Expected)
		check(s.ID, s.FalsePositives)
		if ids[s.ID] {
			t.Errorf("truth: id %s listed twice", s.ID)
		}
		ids[s.ID] = true
		for _, fp := range s.FalsePositives {
			if toSet(s.Expected)[fp] {
				t.Errorf("truth %s: %s is both expected and a false positive", s.ID, fp)
			}
		}
	}
}

func TestParseLabels(t *testing.T) {
	l, err := parseLabels("# comment\n\na.com React, Next.js\nb.com\nc.com Ruby on Rails\n", []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	want := []corpusSite{
		{Host: "a.com", Expected: []string{"React", "Next.js"}},
		{Host: "b.com"},
		{Host: "c.com", Expected: []string{"Ruby on Rails"}},
	}
	if !reflect.DeepEqual(l.corpus, want) {
		t.Errorf("got %+v, want %+v", l.corpus, want)
	}
	if _, err := parseLabels("https://a.com/ React\n", []byte("[]")); err == nil {
		t.Error("a URL instead of a host parsed")
	}
}

func TestScore(t *testing.T) {
	l := &labels{
		corpus: []corpusSite{
			{Host: "a.com", Expected: []string{"React"}},
			{Host: "b.com", Expected: []string{"Vue.js", "Nuxt.js"}},
		},
		truth: []truthSite{
			{ID: "01", Expected: []string{"React", "Next.js"}, FalsePositives: []string{"jQuery"}},
			{ID: "02", Expected: []string{"Drupal"}},
		},
	}
	r := &results{
		Corpus: map[string][]string{"a.com": {"React", "jQuery"}, "b.com": {"Vue.js", "jQuery"}},
		Truth:  map[string][]string{"01": {"React", "jQuery", "Lodash"}},
	}
	cs := scoreCorpus(l, r)
	if cs.found != 2 || cs.expected != 3 || cs.detections != 4 || cs.pages != 2 {
		t.Errorf("corpus: %+v", cs)
	}
	if !reflect.DeepEqual(cs.misses, []string{"b.com:Nuxt.js"}) {
		t.Errorf("corpus misses: %v", cs.misses)
	}
	// jQuery is on both pages, React and Vue.js on one each: all above 20%.
	if len(cs.noisy) != 3 || cs.noisy[0] != (count{"jQuery", 2}) {
		t.Errorf("corpus noisy: %v", cs.noisy)
	}

	ts := scoreTruth(l, r)
	// Page 02 wasn't analyzed: its techs count as missed.
	if ts.found != 1 || ts.expected != 3 || ts.knownFP != 1 || ts.unlabeled != 1 || ts.pages != 1 || ts.missing != 1 {
		t.Errorf("truth: %+v", ts)
	}

	if got, want := techDiff([]string{"React", "jQuery"}, []string{"Next.js", "React"}, toSet([]string{"Next.js"}), toSet([]string{"jQuery"})),
		"+Next.js (expected), -jQuery (false positive)"; got != want {
		t.Errorf("techDiff: %q, want %q", got, want)
	}
}

func TestReplay(t *testing.T) {
	c, err := openCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.assets.put("https://a.com/app.js", 200, "text/javascript", []byte("var x;")); err != nil {
		t.Fatal(err)
	}
	if err := c.assets.save(); err != nil {
		t.Fatal(err)
	}
	c, err = openCache(c.dir)
	if err != nil {
		t.Fatal(err)
	}
	replay := &replayTransport{store: c.assets, missed: map[string]bool{}}
	client := &http.Client{Transport: replay}

	resp, err := client.Get("https://a.com/app.js")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "var x;" || resp.Header.Get("Content-Type") != "text/javascript" {
		t.Errorf("cached asset: %d %q %q", resp.StatusCode, body, resp.Header.Get("Content-Type"))
	}
	resp, err = client.Get("https://a.com/other.js")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 404 {
		t.Errorf("uncached asset: status %d, want 404", resp.StatusCode)
	}
	if got := replay.missedURLs(); !reflect.DeepEqual(got, []string{"https://a.com/other.js"}) {
		t.Errorf("missed: %v", got)
	}
}

func TestResults(t *testing.T) {
	c, err := openCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := &results{Tag: "before", Corpus: map[string][]string{"a.com": {"React"}}}
	if err := c.saveResults(r); err != nil {
		t.Fatal(err)
	}
	got, err := c.loadResults("before")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Corpus, r.Corpus) {
		t.Errorf("loaded %v, want %v", got.Corpus, r.Corpus)
	}
	if _, err := c.loadResults(filepath.Join(c.resultsDir(), "before.json")); err != nil {
		t.Errorf("loading by path: %v", err)
	}
	if err := c.saveResults(&results{Tag: "../x"}); err == nil {
		t.Error("saved results with a tag that is a path")
	}
}

func TestReadCurlPage(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "01")
	files := map[string]string{
		".meta": "200 https://www.a.com/\n",
		".hdr":  "HTTP/1.1 301 Moved Permanently\r\nLocation: https://www.a.com/\r\n\r\nHTTP/2 200\r\ncontent-type: text/html\r\nx-a: 1\r\n\r\n",
		".html": "<html></html>",
	}
	for ext, data := range files {
		if err := os.WriteFile(base+ext, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	p, responses, err := readCurlPage(base)
	if err != nil {
		t.Fatal(err)
	}
	if responses != 2 || p.Status != 200 || p.Final != "https://www.a.com/" || string(p.Body) != "<html></html>" {
		t.Errorf("got %d responses, page %+v", responses, p)
	}
	want := map[string][]string{"content-type": {"text/html"}, "x-a": {"1"}}
	if !reflect.DeepEqual(p.Headers, want) {
		t.Errorf("headers %v, want those of the last response %v", p.Headers, want)
	}
}
