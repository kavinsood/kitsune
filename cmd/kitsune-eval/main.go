// Command kitsune-eval measures how well kitsune detects techs, on two
// labeled sets of pages:
//
//   - corpus (corpus.txt): 45 well-known sites, each with the few techs it is
//     known for. Pages are analyzed without their URL (Fingerprint), so
//     without DNS and with only the assets they link by absolute URL.
//   - truth (truth.json): 37 sites whose techs were checked by hand, with the
//     techs known to be detected falsely on them. Pages go through the full
//     pipeline at their final URL, as in the API (FingerprintWithURL), with
//     their DNS records and the scripts and stylesheets they link.
//
// The pages, their DNS records and their assets are downloaded once into a
// cache (cmd/kitsune-eval/cache, git-ignored), and every run is served from
// it, offline, so that builds are compared on the same snapshot. Live sites
// change, so a snapshot drifts away from the labels over time; the date it
// was taken is printed with the scores. See README.md.
//
// Usage, from the root of the repository:
//
//	go run ./cmd/kitsune-eval [-tag name] [-compare tag]  # fetch what's missing, run, score
//	go run ./cmd/kitsune-eval fetch [-refresh]            # only fetch
//	go run ./cmd/kitsune-eval diff old new                # compare two saved results
//	go run ./cmd/kitsune-eval import -corpus dir -truth dir -cache dir
package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/kavinsood/kitsune/internal/profiler"
)

var (
	//go:embed corpus.txt
	corpusLabels string
	//go:embed truth.json
	truthLabels []byte
)

// corpusSite is a site of the corpus set and the techs expected on it.
type corpusSite struct {
	Host     string
	Expected []string
}

// truthSite is a hand-checked site of the truth set.
type truthSite struct {
	ID       string   `json:"id"`
	URL      string   `json:"url"`
	Name     string   `json:"name"`
	Expected []string `json:"expected"`
	// FalsePositives are techs the site doesn't use that have been
	// detected on it.
	FalsePositives []string `json:"false_positives"`
}

type labels struct {
	corpus []corpusSite
	truth  []truthSite
}

func parseLabels(corpusText string, truthJSON []byte) (*labels, error) {
	l := &labels{}
	for i, line := range strings.Split(corpusText, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		host, techs, _ := strings.Cut(line, " ")
		site := corpusSite{Host: host}
		for _, t := range strings.Split(techs, ",") {
			if t = strings.TrimSpace(t); t != "" {
				site.Expected = append(site.Expected, t)
			}
		}
		if strings.Contains(host, "/") {
			return nil, fmt.Errorf("corpus.txt:%d: %q is not a host", i+1, host)
		}
		l.corpus = append(l.corpus, site)
	}
	if err := json.Unmarshal(truthJSON, &l.truth); err != nil {
		return nil, fmt.Errorf("truth.json: %w", err)
	}
	return l, nil
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("kitsune-eval: ")

	args := os.Args[1:]
	cmd := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "run", "fetch", "diff", "import":
	default:
		fmt.Fprintln(os.Stderr, "usage: kitsune-eval [run|fetch|diff|import] [flags]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("kitsune-eval "+cmd, flag.ExitOnError)
	cacheDir := fs.String("cache", "", "cache directory (default cmd/kitsune-eval/cache in the repository)")
	tag := fs.String("tag", "", "run: name to save the results under (default the git commit)")
	compare := fs.String("compare", "", "run: saved results to compare with")
	refresh := fs.Bool("refresh", false, "run, fetch: download all pages again, starting a new snapshot")
	offline := fs.Bool("offline", false, "run: don't download missing pages")
	verbose := fs.Bool("v", false, "run: list the requests the snapshot couldn't serve")
	importCorpus := fs.String("corpus", "", "import: directory of corpus pages saved as JSON records (<host>.json)")
	importTruth := fs.String("truth", "", "import: directory of truth pages saved by curl (NN.meta, NN.hdr, NN.html)")
	fs.Parse(args)

	l, err := parseLabels(corpusLabels, truthLabels)
	if err != nil {
		log.Fatal(err)
	}
	if *cacheDir == "" {
		root, err := repoRoot()
		if err != nil {
			log.Fatal(err)
		}
		*cacheDir = filepath.Join(root, "cmd", "kitsune-eval", "cache")
	}
	c, err := openCache(*cacheDir)
	if err != nil {
		log.Fatal(err)
	}

	switch cmd {
	case "diff":
		if fs.NArg() != 2 {
			log.Fatal("usage: kitsune-eval diff old new")
		}
		a, err := c.loadResults(fs.Arg(0))
		if err != nil {
			log.Fatal(err)
		}
		b, err := c.loadResults(fs.Arg(1))
		if err != nil {
			log.Fatal(err)
		}
		printDiff(os.Stdout, l, a, b)
		return
	case "import":
		if err := c.importPages(l, *importCorpus, *importTruth); err != nil {
			log.Fatal(err)
		}
	}

	engine, err := profiler.New()
	if err != nil {
		log.Fatal(err)
	}
	if *refresh {
		if err := c.clear(); err != nil {
			log.Fatal(err)
		}
	}
	if !*offline {
		if err := c.complete(engine, l); err != nil {
			log.Fatal(err)
		}
	}
	if cmd != "run" {
		fmt.Println(c.describe())
		return
	}

	res := c.run(engine, l)
	res.Tag = *tag
	if res.Tag == "" {
		res.Tag = res.Commit
	}
	if res.Tag == "" {
		res.Tag = "local"
	}
	printScores(os.Stdout, l, res, *verbose)
	if err := c.saveResults(res); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("\nsaved as %q in %s\n", res.Tag, c.resultsDir())
	if *compare != "" {
		old, err := c.loadResults(*compare)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println()
		printDiff(os.Stdout, l, old, res)
	}
}

// repoRoot returns the directory of go.mod, above the working directory.
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("not in the repository (no go.mod above the working directory); use -cache")
		}
		dir = parent
	}
}

// gitCommit describes the checked-out commit, like "ff00e92" or
// "ff00e92-dirty" with uncommitted changes, or "" outside git.
func gitCommit() string {
	out, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		return ""
	}
	commit := strings.TrimSpace(string(out))
	if st, err := exec.Command("git", "status", "--porcelain", "--untracked-files=no").Output(); err == nil && len(st) > 0 {
		commit += "-dirty"
	}
	return commit
}

// realTransport is the transport the cache downloads with. Runs replace
// http.DefaultTransport, which the profiler's asset fetcher uses.
var realTransport http.RoundTripper = http.DefaultTransport.(*http.Transport).Clone()
