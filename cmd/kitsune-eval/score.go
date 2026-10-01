package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/kavinsood/kitsune/internal/profiler"
)

// results are the techs detected on the pages of a snapshot by a build.
type results struct {
	Tag      string    `json:"tag"`
	Commit   string    `json:"commit"`
	Created  time.Time `json:"created"`
	Snapshot snapshot  `json:"snapshot"`
	// Techs is how many techs the build has fingerprints for.
	Techs int `json:"techs"`
	// Corpus and Truth hold the techs detected per corpus host and truth
	// id. Pages missing from the snapshot are absent, as are truth pages
	// that weren't served with status 200, whose status is in Skipped.
	Corpus  map[string][]string `json:"corpus"`
	Truth   map[string][]string `json:"truth"`
	Skipped map[string]int      `json:"skipped,omitempty"`
	// Uncached are the URLs the analysis requested that the snapshot
	// doesn't have, which were served as 404s.
	Uncached []string `json:"uncached,omitempty"`
}

// run analyzes the pages of the cache, offline: assets are served from the
// cache and DNS records from the truth pages. Pages are analyzed one at a
// time, so that timeouts depend as little as possible on the machine.
func (c *cache) run(engine *profiler.Wappalyze, l *labels) *results {
	res := &results{
		Commit:   gitCommit(),
		Created:  time.Now().UTC().Truncate(time.Second),
		Snapshot: c.snap,
		Techs:    len(engine.GetCompiledFingerprints().Apps),
		Corpus:   map[string][]string{},
		Truth:    map[string][]string{},
		Skipped:  map[string]int{},
	}
	fail := func(err error) { fmt.Fprintf(os.Stderr, "kitsune-eval: %v\n", err) }

	type item struct {
		set, name string
		p         *page
	}
	var items []item
	dns := map[string]map[string][]string{}
	for _, s := range l.corpus {
		p, err := c.loadPage("corpus", s.Host)
		if err != nil {
			fail(err)
		}
		items = append(items, item{"corpus", s.Host, p})
	}
	for _, s := range l.truth {
		p, err := c.loadPage("truth", s.ID)
		if err != nil {
			fail(err)
		}
		items = append(items, item{"truth", s.ID, p})
		if p != nil {
			if u, err := url.Parse(p.Final); err == nil {
				dns[u.Hostname()] = p.DNS
			}
		}
	}

	replay := &replayTransport{store: c.assets, missed: map[string]bool{}}
	oldTransport, oldDNS := http.DefaultTransport, profiler.LookupDNS
	http.DefaultTransport = replay
	profiler.LookupDNS = func(host string) map[string][]string { return dns[host] }
	for _, it := range items {
		if it.p == nil {
			continue
		}
		techs, ok := analyze(engine, it.set, it.p)
		switch {
		case !ok:
			res.Skipped[it.name] = it.p.Status
		case it.set == "corpus":
			res.Corpus[it.name] = techNames(techs)
		default:
			res.Truth[it.name] = techNames(techs)
		}
	}
	http.DefaultTransport, profiler.LookupDNS = oldTransport, oldDNS
	res.Uncached = replay.missedURLs()
	return res
}

// techNames returns the sorted names of the detected techs, without their
// versions.
func techNames(detected map[string]struct{}) []string {
	names := make([]string, 0, len(detected))
	for k := range detected {
		name, _, _ := strings.Cut(k, ":")
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

type corpusScore struct {
	found, expected int
	pages, missing  int
	detections      int
	misses          []string // host:tech
	noisy           []count  // techs on more than noiseShare of the pages
}

// noiseShare is the share of corpus pages above which a tech is listed as
// noisy: few techs are really on that many sites.
const noiseShare = 0.2

type truthScore struct {
	found, expected     int
	pages, missing      int
	knownFP, unlabeled  int
	detections          int
	fps, misses, unlabs []count
}

type count struct {
	name string
	n    int
}

func scoreCorpus(l *labels, r *results) corpusScore {
	var s corpusScore
	freq := map[string]int{}
	for _, site := range l.corpus {
		got, ok := r.Corpus[site.Host]
		if !ok {
			s.missing++
		}
		set := toSet(got)
		for _, t := range site.Expected {
			s.expected++
			if set[t] {
				s.found++
			} else {
				s.misses = append(s.misses, site.Host+":"+t)
			}
		}
	}
	for _, techs := range r.Corpus {
		s.pages++
		s.detections += len(techs)
		for _, t := range techs {
			freq[t]++
		}
	}
	for _, c := range sortCounts(freq) {
		if float64(c.n) > noiseShare*float64(s.pages) {
			s.noisy = append(s.noisy, c)
		}
	}
	return s
}

func scoreTruth(l *labels, r *results) truthScore {
	var s truthScore
	fps, misses, unlabs := map[string]int{}, map[string]int{}, map[string]int{}
	for _, site := range l.truth {
		s.expected += len(site.Expected)
		got, ok := r.Truth[site.ID]
		if !ok {
			s.missing++
		} else {
			s.pages++
		}
		set := toSet(got)
		for _, t := range site.Expected {
			if set[t] {
				s.found++
			} else {
				misses[t]++
			}
		}
		s.detections += len(got)
		labeled := toSet(site.Expected)
		for _, t := range site.FalsePositives {
			labeled[t] = true
			if set[t] {
				s.knownFP++
				fps[t]++
			}
		}
		for _, t := range got {
			if !labeled[t] {
				s.unlabeled++
				unlabs[t]++
			}
		}
	}
	s.fps, s.misses, s.unlabs = sortCounts(fps), sortCounts(misses), sortCounts(unlabs)
	return s
}

func printScores(w io.Writer, l *labels, r *results, verbose bool) {
	fmt.Fprintf(w, "%s (%s), %d techs\n", r.Tag, r.Commit, r.Techs)
	fmt.Fprintf(w, "snapshot %s\n\n", describeSnapshot(r.Snapshot))

	cs := scoreCorpus(l, r)
	fmt.Fprintf(w, "corpus: %d/%d expected found, %d detections on %d pages\n", cs.found, cs.expected, cs.detections, cs.pages)
	if cs.missing > 0 {
		fmt.Fprintf(w, "  %d pages missing from the snapshot\n", cs.missing)
	}
	fmt.Fprintf(w, "  missed: %s\n", orNone(strings.Join(cs.misses, ", ")))
	fmt.Fprintf(w, "  on >%d%% of pages: %s\n", int(noiseShare*100), formatCounts(cs.noisy, 0))

	ts := scoreTruth(l, r)
	fmt.Fprintf(w, "\ntruth: %d/%d expected found, %d known false positives, %d unlabeled, %d detections on %d pages\n",
		ts.found, ts.expected, ts.knownFP, ts.unlabeled, ts.detections, ts.pages)
	if ts.missing > 0 {
		var why []string
		for _, site := range l.truth {
			if st, ok := r.Skipped[site.ID]; ok {
				why = append(why, fmt.Sprintf("%s %s: status %d", site.ID, site.Name, st))
			} else if _, ok := r.Truth[site.ID]; !ok {
				why = append(why, fmt.Sprintf("%s %s: missing", site.ID, site.Name))
			}
		}
		fmt.Fprintf(w, "  %d pages not analyzed, their techs counted as missed: %s\n", ts.missing, strings.Join(why, ", "))
	}
	fmt.Fprintf(w, "  known false positives: %s\n", formatCounts(ts.fps, 0))
	fmt.Fprintf(w, "  missed: %s\n", formatCounts(ts.misses, 0))
	fmt.Fprintf(w, "  unlabeled: %s\n", formatCounts(ts.unlabs, 30))
	if len(r.Uncached) > 0 {
		fmt.Fprintf(w, "  %d requests not in the snapshot, served as 404s", len(r.Uncached))
		if verbose {
			fmt.Fprintf(w, ":\n    %s\n", strings.Join(r.Uncached, "\n    "))
		} else {
			fmt.Fprintf(w, " (-v lists them)\n")
		}
	}
}

// printDiff compares results b with the older a: scores, then the techs
// gained and lost on each page.
func printDiff(w io.Writer, l *labels, a, b *results) {
	fmt.Fprintf(w, "%s -> %s\n", a.Tag, b.Tag)
	if !a.Snapshot.Created.Equal(b.Snapshot.Created) {
		fmt.Fprintf(w, "warning: different snapshots, so changes may come from the pages:\n  %s: %s\n  %s: %s\n",
			a.Tag, describeSnapshot(a.Snapshot), b.Tag, describeSnapshot(b.Snapshot))
	}
	ca, cb := scoreCorpus(l, a), scoreCorpus(l, b)
	ta, tb := scoreTruth(l, a), scoreTruth(l, b)
	fmt.Fprintf(w, "corpus: found %s/%d, detections %s\n", delta(ca.found, cb.found), cb.expected, delta(ca.detections, cb.detections))
	fmt.Fprintf(w, "truth:  found %s/%d, known false positives %s, unlabeled %s, detections %s\n",
		delta(ta.found, tb.found), tb.expected, delta(ta.knownFP, tb.knownFP), delta(ta.unlabeled, tb.unlabeled), delta(ta.detections, tb.detections))

	var lines []string
	for _, s := range l.corpus {
		if line := techDiff(a.Corpus[s.Host], b.Corpus[s.Host], toSet(s.Expected), nil); line != "" {
			lines = append(lines, fmt.Sprintf("  %-22s %s", s.Host, line))
		}
	}
	fmt.Fprintf(w, "\ncorpus changes:\n%s\n", orNone(strings.Join(lines, "\n")))
	lines = nil
	for _, s := range l.truth {
		if line := techDiff(a.Truth[s.ID], b.Truth[s.ID], toSet(s.Expected), toSet(s.FalsePositives)); line != "" {
			lines = append(lines, fmt.Sprintf("  %-25s %s", s.ID+" "+s.Name, line))
		}
	}
	fmt.Fprintf(w, "\ntruth changes:\n%s\n", orNone(strings.Join(lines, "\n")))
}

// techDiff lists the techs of b not in a (+) and of a not in b (-), noting
// those expected and those known to be false positives.
func techDiff(a, b []string, expected, falsePos map[string]bool) string {
	as, bs := toSet(a), toSet(b)
	note := func(t string) string {
		switch {
		case expected[t]:
			return t + " (expected)"
		case falsePos[t]:
			return t + " (false positive)"
		}
		return t
	}
	var out []string
	for _, t := range b {
		if !as[t] {
			out = append(out, "+"+note(t))
		}
	}
	for _, t := range a {
		if !bs[t] {
			out = append(out, "-"+note(t))
		}
	}
	return strings.Join(out, ", ")
}

func delta(a, b int) string {
	if a == b {
		return fmt.Sprint(b)
	}
	return fmt.Sprintf("%d -> %d (%+d)", a, b, b-a)
}

func toSet(s []string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, v := range s {
		m[v] = true
	}
	return m
}

// sortCounts returns the counts most frequent first.
func sortCounts(m map[string]int) []count {
	out := make([]count, 0, len(m))
	for k, n := range m {
		out = append(out, count{k, n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].n != out[j].n {
			return out[i].n > out[j].n
		}
		return out[i].name < out[j].name
	})
	return out
}

// formatCounts lists counts as "name n", the first max of them if max > 0.
func formatCounts(cs []count, max int) string {
	var parts []string
	for i, c := range cs {
		if max > 0 && i == max {
			parts = append(parts, fmt.Sprintf("... (%d more)", len(cs)-max))
			break
		}
		parts = append(parts, fmt.Sprintf("%s %d", c.name, c.n))
	}
	return orNone(strings.Join(parts, ", "))
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
