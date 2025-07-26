package pipeline

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const wappalyzerURL = "https://addons.mozilla.org/firefox/downloads/latest/wappalyzer/platform:2/wappalyzer.xpi"

// FetchFromXPI downloads the wappalyzer extension, extracts technology and category
// data in memory, and returns them.
func FetchFromXPI() (map[string]interface{}, []byte, error) {
	// Step 1: Download the XPI into an in-memory buffer.
	resp, err := http.Get(wappalyzerURL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to download XPI: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("bad status code fetching XPI: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read XPI response body: %w", err)
	}

	// Step 2: Use an in-memory zip reader.
	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create zip reader: %w", err)
	}

	// Step 3: Iterate, find files, and merge/extract.
	mergedApps := make(map[string]interface{})
	var categoriesData []byte

	for _, file := range zipReader.File {
		// A. Find and merge all technology definitions.
		if strings.HasPrefix(file.Name, "technologies/") && strings.HasSuffix(file.Name, ".json") {
			rc, err := file.Open()
			if err != nil {
				return nil, nil, fmt.Errorf("failed to open %s from zip: %w", file.Name, err)
			}

			var techData map[string]interface{}
			if err := json.NewDecoder(rc).Decode(&techData); err != nil {
				rc.Close()
				return nil, nil, fmt.Errorf("failed to decode %s: %w", file.Name, err)
			}
			rc.Close()

			// Merge into the master map.
			for key, val := range techData {
				mergedApps[key] = val
			}
		}

		// B. Find and extract the raw categories.json content.
		if file.Name == "categories.json" {
			rc, err := file.Open()
			if err != nil {
				return nil, nil, fmt.Errorf("failed to open categories.json from zip: %w", err)
			}
			categoriesData, err = io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read categories.json: %w", err)
			}
		}
	}

	if len(mergedApps) == 0 {
		return nil, nil, fmt.Errorf("no technologies were found in the XPI")
	}
	if len(categoriesData) == 0 {
		return nil, nil, fmt.Errorf("categories.json was not found in the XPI")
	}

	return mergedApps, categoriesData, nil
}
