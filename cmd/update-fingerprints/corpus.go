package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kavinsood/kitsune/internal/profiler"
)

// corpusRecord is a saved page: the response to a GET of URL.
type corpusRecord struct {
	URL     string
	Final   string
	Status  int
	Headers map[string][]string
	Body    []byte
}

// noisyTech is a tech detected on many pages of a corpus.
type noisyTech struct {
	name  string
	pages int
}

// corpusNoise runs the engine with the fingerprints in fingerprintsFile
// over the pages saved as JSON corpusRecords in dir. It returns the number
// of pages and the techs detected on more than threshold of them, most
// frequent first. Such techs are rarely on that many sites: they usually
// have a pattern that matches too much.
func corpusNoise(fingerprintsFile, dir string, threshold float64) (int, []noisyTech, error) {
	wappalyzer, err := profiler.NewFromFile(fingerprintsFile, false, false)
	if err != nil {
		return 0, nil, err
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return 0, nil, err
	}
	if len(files) == 0 {
		return 0, nil, fmt.Errorf("no *.json pages in %s", dir)
	}
	counts := make(map[string]int)
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return 0, nil, err
		}
		var rec corpusRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			return 0, nil, fmt.Errorf("%s: %w", file, err)
		}
		for tech := range wappalyzer.Fingerprint(rec.Headers, rec.Body) {
			name, _, _ := strings.Cut(tech, ":")
			counts[name]++
		}
	}
	var noisy []noisyTech
	for name, n := range counts {
		if float64(n) > threshold*float64(len(files)) {
			noisy = append(noisy, noisyTech{name, n})
		}
	}
	sort.Slice(noisy, func(i, j int) bool {
		if noisy[i].pages != noisy[j].pages {
			return noisy[i].pages > noisy[j].pages
		}
		return noisy[i].name < noisy[j].name
	})
	return len(files), noisy, nil
}
