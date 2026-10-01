package main

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

// Pinned commits of the GitHub sources. Override them with -enthec-ref and
// -httparchive-ref (which also take branch names such as main).
const (
	enthecRef      = "eea872af449e207e055398f7369d11ee48c8ea03"
	httparchiveRef = "20436693e89619e5e7eb5237576ec970ce688127"
)

// The latest releases of the Wappalyzer extension: for Firefox, from
// addons.mozilla.org, and for Chrome, from the Chrome Web Store. The Chrome
// Web Store usually gets a release first.
const (
	extensionURL = "https://addons.mozilla.org/firefox/downloads/latest/wappalyzer/wappalyzer.xpi"
	chromeURL    = "https://clients2.google.com/service/update2/crx?response=redirect&prodversion=140.0&acceptformat=crx2,crx3&x=id%3Dgppongmhjkpfnbhagpmjfkannfbllamg%26uc"
)

// sourceSpec describes where to get a source.
type sourceSpec struct {
	name string
	// url returns the URL of the archive of the source at ref.
	url func(ref string) string
	ref string
	// local is a local copy (a directory or a .zip/.xpi/.crx archive) to
	// use instead of downloading, if set.
	local string
}

func githubArchive(repo string) func(string) string {
	return func(ref string) string {
		return "https://github.com/" + repo + "/archive/" + ref + ".zip"
	}
}

// source is a source loaded and normalized.
type source struct {
	name string
	// version is the version of the source: the extension's version or the
	// git ref.
	version string
	// manifest is the extension's version, if the source is an extension.
	manifest   string
	techs      map[string]*Tech
	categories map[string]*Category
}

// Category is a category in the format of assets/categories_data.json.
type Category struct {
	Groups      []int  `json:"groups,omitempty"`
	Name        string `json:"name"`
	Priority    int    `json:"priority"`
	Description string `json:"description,omitempty"`
}

// loadSource loads the source spec describes.
func loadSource(spec sourceSpec, stats counter) (*source, error) {
	fsys, version, err := openSource(spec)
	if err != nil {
		return nil, err
	}
	root, err := findRoot(fsys)
	if err != nil {
		return nil, err
	}
	if root != "." {
		if fsys, err = fs.Sub(fsys, root); err != nil {
			return nil, err
		}
	}
	src := &source{name: spec.name, version: version}
	if v := manifestVersion(fsys); v != "" {
		src.manifest = v
		src.version = v + ", " + version
	}
	if src.techs, err = readTechs(fsys, stats); err != nil {
		return nil, err
	}
	if src.categories, err = readCategories(fsys); err != nil {
		return nil, err
	}
	return src, nil
}

// openSource returns the file system of the source spec describes, and its
// version as far as it is known.
func openSource(spec sourceSpec) (fs.FS, string, error) {
	if spec.local != "" {
		info, err := os.Stat(spec.local)
		if err != nil {
			return nil, "", err
		}
		version := "local " + spec.local
		if info.IsDir() {
			return os.DirFS(spec.local), version, nil
		}
		data, err := os.ReadFile(spec.local)
		if err != nil {
			return nil, "", err
		}
		r, err := openZip(data)
		if err != nil {
			return nil, "", fmt.Errorf("%s: %w", spec.local, err)
		}
		return r, version, nil
	}

	url := spec.url(spec.ref)
	log.Printf("%s: downloading %s", spec.name, url)
	data, err := download(url)
	if err != nil {
		return nil, "", err
	}
	r, err := openZip(data)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", url, err)
	}
	return r, spec.ref, nil
}

// openZip opens a zip archive, or a Chrome extension: a zip archive after
// a CRX header.
func openZip(data []byte) (*zip.Reader, error) {
	if bytes.HasPrefix(data, []byte("Cr24")) {
		var err error
		if data, err = stripCRX(data); err != nil {
			return nil, err
		}
	}
	return zip.NewReader(bytes.NewReader(data), int64(len(data)))
}

// stripCRX returns the zip archive in a CRX file.
func stripCRX(data []byte) ([]byte, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("short CRX header")
	}
	version := binary.LittleEndian.Uint32(data[4:8])
	var start uint64
	switch version {
	case 2:
		// Public key and signature lengths follow the version.
		if len(data) < 16 {
			return nil, fmt.Errorf("short CRX2 header")
		}
		start = 16 + uint64(binary.LittleEndian.Uint32(data[8:12])) + uint64(binary.LittleEndian.Uint32(data[12:16]))
	case 3:
		start = 12 + uint64(binary.LittleEndian.Uint32(data[8:12]))
	default:
		return nil, fmt.Errorf("unknown CRX version %d", version)
	}
	if start > uint64(len(data)) {
		return nil, fmt.Errorf("CRX header longer than the file")
	}
	return data[start:], nil
}

// maxDownload bounds the size of a downloaded archive.
const maxDownload = 512 << 20

func download(url string) ([]byte, error) {
	client := &http.Client{Timeout: 5 * time.Minute}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	// AMO turns away clients that don't look like browsers.
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDownload+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", url, err)
	}
	if len(data) > maxDownload {
		return nil, fmt.Errorf("%s: larger than %d bytes", url, maxDownload)
	}
	return data, nil
}

// findRoot returns the directory of fsys holding the technologies
// directory: the root (the extension), src (a repository), or either inside
// a single top-level directory (a GitHub archive).
func findRoot(fsys fs.FS) (string, error) {
	candidates := []string{".", "src"}
	if entries, err := fs.ReadDir(fsys, "."); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				candidates = append(candidates, e.Name(), path.Join(e.Name(), "src"))
			}
		}
	}
	for _, dir := range candidates {
		if info, err := fs.Stat(fsys, path.Join(dir, "technologies")); err == nil && info.IsDir() {
			return dir, nil
		}
	}
	return "", fmt.Errorf("no technologies directory found")
}

func manifestVersion(fsys fs.FS) string {
	data, err := fs.ReadFile(fsys, "manifest.json")
	if err != nil {
		return ""
	}
	var manifest struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(data, &manifest) != nil {
		return ""
	}
	return manifest.Version
}

// readTechs reads and normalizes the techs in technologies/*.json. A tech
// in several files is taken from the last, as Wappalyzer does.
func readTechs(fsys fs.FS, stats counter) (map[string]*Tech, error) {
	files, err := fs.Glob(fsys, "technologies/*.json")
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no technologies/*.json files")
	}
	sort.Strings(files)
	n := &normalizer{stats: stats, split: true}
	techs := make(map[string]*Tech)
	for _, file := range files {
		data, err := fs.ReadFile(fsys, file)
		if err != nil {
			return nil, err
		}
		var raws map[string]*rawTech
		if err := json.Unmarshal(data, &raws); err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		for _, name := range sortedKeys(raws) {
			t, err := n.normalize(raws[name])
			if err != nil {
				return nil, fmt.Errorf("%s: %s: %w", file, name, err)
			}
			techs[name] = t
		}
	}
	return techs, nil
}

func readCategories(fsys fs.FS) (map[string]*Category, error) {
	data, err := fs.ReadFile(fsys, "categories.json")
	if err != nil {
		return nil, err
	}
	var cats map[string]*Category
	if err := json.Unmarshal(data, &cats); err != nil {
		return nil, fmt.Errorf("categories.json: %w", err)
	}
	return cats, nil
}

// mergeCategories returns the union of the categories of the sources, which
// are in rank order. Each category's fields come from the highest-ranked
// source that has them.
func mergeCategories(sources []*source) (map[string]*Category, []string) {
	out := make(map[string]*Category)
	var conflicts []string
	for _, src := range sources {
		for _, id := range sortedKeys(src.categories) {
			c := src.categories[id]
			cur, ok := out[id]
			if !ok {
				cp := *c
				out[id] = &cp
				continue
			}
			if cur.Name != c.Name {
				conflicts = append(conflicts, fmt.Sprintf("category %s: %q in a higher-ranked source, %q in %s", id, cur.Name, c.Name, src.name))
			}
			if cur.Description == "" {
				cur.Description = c.Description
			}
			if len(cur.Groups) == 0 {
				cur.Groups = c.Groups
			}
		}
	}
	return out, conflicts
}

// sourceNames returns the names of the sources, for messages.
func sourceNames(specs []sourceSpec) string {
	names := make([]string, len(specs))
	for i, s := range specs {
		names[i] = s.name
	}
	return strings.Join(names, ",")
}
