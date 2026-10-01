// Command update-fingerprints builds kitsune's fingerprints,
// assets/fingerprints_data.json and assets/categories_data.json, from
// several Wappalyzer-format sources, merged into one dataset with as much
// coverage as they give together.
//
// The sources, highest-ranked first (see merge.go for what ranking means):
//
//   - chrome: the latest Wappalyzer Chrome extension, from the Chrome Web
//     Store;
//   - extension: the latest Wappalyzer Firefox extension, from
//     addons.mozilla.org;
//   - enthec: github.com/enthec/webappanalyzer, at a pinned commit;
//   - httparchive: github.com/HTTPArchive/wappalyzer, at a pinned commit.
//
// The two extensions are ranked by version, newest first, whatever their
// order in -sources: the stores don't always get a release at the same time.
//
// The update proceeds in steps:
//
//  1. Each source is normalized into kitsune's format (see Tech): every
//     field gets one shape, header, cookie and meta names are lowercased,
//     and dom rules take their object form.
//  2. The sources are merged (merge.go).
//     Before that, patterns written for JavaScript's regex engine are
//     rewritten into RE2 where possible (rewrite.go), and the patterns and
//     dom selectors that the engine still couldn't compile are dropped.
//  3. assets/overrides.json, kitsune's own fixes and additions, is applied
//     (overrides.go).
//  4. Techs that lost all their patterns are reported.
//  5. Patterns for the Content-Security-Policy header are down-ranked
//     (transform.go).
//  6. The result is checked (lint.go). New errors fail the run: errors are
//     compared with those accepted in assets/lint_baseline.txt, which
//     -accept-lint rewrites.
//
// Run it from the root of the repository, then regenerate the compiled
// fingerprints:
//
//	go run ./cmd/update-fingerprints
//	go generate ./internal/profiler
//
// To run offline, point it at local copies of the sources (directories, or
// .crx/.xpi/.zip archives) with -chrome, -extension, -enthec and
// -httparchive.
package main

import (
	"bufio"
	"bytes"
	"cmp"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
)

var (
	fingerprintsOut = flag.String("fingerprints", "assets/fingerprints_data.json", "file to write the fingerprints to")
	categoriesOut   = flag.String("categories", "assets/categories_data.json", "file to write the categories to")
	overridesFlag   = flag.String("overrides", "assets/overrides.json", "overrides file to apply (empty for none)")
	baselineFlag    = flag.String("lint-baseline", "assets/lint_baseline.txt", "file of accepted lint errors")
	acceptLint      = flag.Bool("accept-lint", false, "accept the current lint errors, rewriting the baseline")
	verbose         = flag.Bool("v", false, "print every lint finding")

	sourcesFlag    = flag.String("sources", "chrome,extension,enthec,httparchive", "sources to merge, highest-ranked first")
	chromePath     = flag.String("chrome", "", "local copy of the Chrome extension (unzipped directory or .crx) to use instead of downloading it")
	extensionPath  = flag.String("extension", "", "local copy of the extension (unzipped directory or .xpi) to use instead of downloading it")
	enthecPath     = flag.String("enthec", "", "local copy of enthec/webappanalyzer (directory or .zip) to use instead of downloading it")
	enthecRefFlag  = flag.String("enthec-ref", enthecRef, "git ref of enthec/webappanalyzer to download")
	httpaPath      = flag.String("httparchive", "", "local copy of HTTPArchive/wappalyzer (directory or .zip) to use instead of downloading it")
	httpaRefFlag   = flag.String("httparchive-ref", httparchiveRef, "git ref of HTTPArchive/wappalyzer to download")
	cspConfidence  = flag.Int("csp-confidence", 25, "confidence to cap Content-Security-Policy header patterns at")
	corpusDir      = flag.String("corpus", "", "directory of saved pages (JSON records) to run the new fingerprints over, listing noisy techs")
	corpusNoiseMax = flag.Float64("corpus-noise", 0.2, "with -corpus, list the techs detected on more than this fraction of pages")
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("update-fingerprints: ")
	flag.Parse()

	specs, err := selectSources(*sourcesFlag)
	if err != nil {
		log.Fatal(err)
	}

	// 1. Load the sources, making every pattern and selector usable by the
	// engine. Doing that before merging lets patterns that only differed in
	// syntax RE2 lacks dedupe.
	stats := make(counter)
	l := newLinter()
	var sources []*source
	before := make(map[string]int)
	for _, spec := range specs {
		src, err := loadSource(spec, stats)
		if err != nil {
			log.Fatalf("%s: %v", spec.name, err)
		}
		for name, t := range src.techs {
			before[name] = max(before[name], signals(t))
		}
		l.fixPatterns(src.techs)
		l.fixSelectors(src.techs)
		sources = append(sources, src)
	}

	rankExtensions(sources)

	// 2. Merge them.
	techs := mergeSources(sources, stats)
	categories, catConflicts := mergeCategories(sources)
	merged := len(techs)

	// 3. Apply the overrides.
	var ovrStats counter
	if *overridesFlag != "" {
		if ovrStats, err = applyOverrides(*overridesFlag, techs, l); err != nil {
			log.Fatal(err)
		}
	}

	// 4. Report the techs left without patterns.
	l.checkSignals(before, techs)

	// 5. Down-rank CSP header patterns.
	downrankCSP(techs, *cspConfidence, stats)

	// 6. Check the result.
	l.check(techs, categories)

	if err := writeJSON(*fingerprintsOut, struct {
		Apps map[string]*Tech `json:"apps"`
	}{techs}); err != nil {
		log.Fatal(err)
	}
	if err := writeJSON(*categoriesOut, categories); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Sources:")
	for _, src := range sources {
		fmt.Printf("  %-12s %5d techs, %3d categories (%s)\n", src.name, len(src.techs), len(src.categories), src.version)
	}
	fmt.Printf("Merged: %d techs; %d after overrides; %d categories\n", merged, len(techs), len(categories))
	printCounter("Merge", stats)
	printCounter("Overrides", ovrStats)
	printCounter("Fixes", l.counts)
	for _, c := range catConflicts {
		fmt.Println("  " + c)
	}
	fmt.Println("Lint:")
	for _, line := range l.summary() {
		fmt.Println("  " + line)
	}
	if *verbose {
		for _, i := range l.sortedIssues() {
			fmt.Printf("  %s %s: %s: %s\n", i.sev, i.kind, i.tech, i.detail)
		}
	} else {
		for _, i := range l.sortedIssues() {
			if i.kind == "override-noop" {
				fmt.Printf("  %s %s: %s: %s\n", i.sev, i.kind, i.tech, i.detail)
			}
		}
	}
	fmt.Printf("Wrote %s and %s\n", *fingerprintsOut, *categoriesOut)

	newErrors, err := checkBaseline(*baselineFlag, l.issues, *acceptLint)
	if err != nil {
		log.Fatal(err)
	}

	if *corpusDir != "" {
		pages, noisy, err := corpusNoise(*fingerprintsOut, *corpusDir, *corpusNoiseMax)
		if err != nil {
			log.Fatalf("corpus: %v", err)
		}
		fmt.Printf("Corpus: %d pages; %d techs detected on more than %.0f%% of them\n", pages, len(noisy), 100**corpusNoiseMax)
		for _, t := range noisy {
			fmt.Printf("  %4d %s\n", t.pages, t.name)
		}
	}

	if len(newErrors) > 0 {
		for _, i := range newErrors {
			fmt.Fprintf(os.Stderr, "new %s %s: %s: %s\n", i.sev, i.kind, i.tech, i.detail)
		}
		log.Fatalf("%d new lint errors; fix them (in the overrides, say) or accept them with -accept-lint", len(newErrors))
	}
}

// selectSources returns the specs of the named sources, in order.
func selectSources(names string) ([]sourceSpec, error) {
	all := map[string]sourceSpec{
		"chrome":      {name: "chrome", url: func(string) string { return chromeURL }, ref: "latest", local: *chromePath},
		"extension":   {name: "extension", url: func(string) string { return extensionURL }, ref: "latest", local: *extensionPath},
		"enthec":      {name: "enthec", url: githubArchive("enthec/webappanalyzer"), ref: *enthecRefFlag, local: *enthecPath},
		"httparchive": {name: "httparchive", url: githubArchive("HTTPArchive/wappalyzer"), ref: *httpaRefFlag, local: *httpaPath},
	}
	var specs []sourceSpec
	for _, name := range strings.Split(names, ",") {
		spec, ok := all[strings.TrimSpace(name)]
		if !ok {
			return nil, fmt.Errorf("unknown source %q", name)
		}
		specs = append(specs, spec)
	}
	if len(specs) == 0 {
		return nil, fmt.Errorf("no sources")
	}
	return specs, nil
}

// rankExtensions reorders the extension sources among the slots they hold
// in sources, newest version first.
func rankExtensions(sources []*source) {
	var slots []int
	var exts []*source
	for i, src := range sources {
		if src.manifest != "" {
			slots = append(slots, i)
			exts = append(exts, src)
		}
	}
	sort.SliceStable(exts, func(i, j int) bool {
		return compareVersions(exts[i].manifest, exts[j].manifest) > 0
	})
	for k, i := range slots {
		sources[i] = exts[k]
	}
}

// compareVersions compares dotted version numbers.
func compareVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < max(len(as), len(bs)); i++ {
		var x, y int
		if i < len(as) {
			x, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			y, _ = strconv.Atoi(bs[i])
		}
		if x != y {
			return cmp.Compare(x, y)
		}
	}
	return 0
}

func printCounter(title string, c counter) {
	if len(c) == 0 {
		return
	}
	fmt.Println(title + ":")
	for _, k := range sortedKeys(c) {
		fmt.Printf("  %6d %s\n", c[k], k)
	}
}

// writeJSON writes v to file as indented JSON with sorted map keys.
func writeJSON(file string, v any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "    ")
	if err := enc.Encode(v); err != nil {
		return err
	}
	return os.WriteFile(file, buf.Bytes(), 0o644)
}

// checkBaseline returns the errors among issues that aren't in the baseline
// file. If accept is set, it instead writes the errors to the baseline.
func checkBaseline(file string, issues []issue, accept bool) ([]issue, error) {
	var errs []issue
	for _, i := range issues {
		if i.sev == sevError {
			errs = append(errs, i)
		}
	}
	if file == "" {
		return nil, nil
	}
	if accept {
		var buf bytes.Buffer
		buf.WriteString("# Lint errors accepted by update-fingerprints -accept-lint: kind, tech, detail.\n")
		buf.WriteString("# New errors fail the update; fix them or accept them.\n")
		keys := make(map[string]bool)
		for _, i := range errs {
			keys[i.key()] = true
		}
		for _, k := range sortedKeys(keys) {
			buf.WriteString(k + "\n")
		}
		fmt.Printf("Accepted %d lint errors into %s\n", len(keys), file)
		return nil, os.WriteFile(file, buf.Bytes(), 0o644)
	}

	accepted := make(map[string]bool)
	if f, err := os.Open(file); err == nil {
		s := bufio.NewScanner(f)
		s.Buffer(nil, 1<<20)
		for s.Scan() {
			if line := s.Text(); line != "" && !strings.HasPrefix(line, "#") {
				accepted[line] = true
			}
		}
		f.Close()
		if err := s.Err(); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	var fresh []issue
	for _, i := range errs {
		if !accepted[i.key()] {
			fresh = append(fresh, i)
		}
	}
	return fresh, nil
}
