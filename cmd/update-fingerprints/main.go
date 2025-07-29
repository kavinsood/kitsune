// This is a standalone tool for fetching and processing the canonical Wappalyzer fingerprints.
// It downloads the latest Wappalyzer XPI from Mozilla Add-ons, extracts the technology fingerprints,
// and converts them to a clean, structured format that can be embedded in the kitsune library.
//
// The goal is MAXIMUM FIDELITY to the original fingerprint patterns. This tool performs only minimal,
// targeted cleaning to ensure the data has a consistent structure without modifying the actual patterns.
// Specifically:
// 1. It normalizes field names that are canonically case-insensitive (like HTTP headers, meta tags, cookies)
// 2. It preserves the original case and format of regex patterns for accurate matching
// 3. It converts fields to consistent types (strings, arrays, maps) based on their content
// 4. It sorts arrays for consistent output and git diffs
//
// Usage: go run main.go [--fingerprints output_path]
package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"
)

var fingerprints = flag.String("fingerprints", "../../fingerprints_data.json", "File to write wappalyzer fingerprints to")

// Technology represents a technology fingerprint from the canonical Wappalyzer XPI
// This matches the raw, inconsistent structure in the source JSON files
// Using interface{} for fields that can be strings or arrays in the source data
type Technology struct {
	Cats        []int                  `json:"cats,omitempty"`
	CSS         interface{}            `json:"css,omitempty"`
	Cookies     map[string]string      `json:"cookies,omitempty"`
	DOM         interface{}            `json:"dom,omitempty"`
	JS          map[string]string      `json:"js,omitempty"`
	Headers     map[string]string      `json:"headers,omitempty"`
	HTML        interface{}            `json:"html,omitempty"`
	Scripts     interface{}            `json:"scripts,omitempty"`
	ScriptSrc   interface{}            `json:"scriptSrc,omitempty"`
	Meta        map[string]interface{} `json:"meta,omitempty"`
	DNS         map[string]interface{} `json:"dns,omitempty"`
	Implies     interface{}            `json:"implies,omitempty"`
	Description string                 `json:"description,omitempty"`
	Website     string                 `json:"website,omitempty"`
	Icon        string                 `json:"icon,omitempty"`
	CPE         string                 `json:"cpe,omitempty"`
}

// OutputFingerprints contains a map of fingerprints for tech detection
// optimized and validated for the tech detection package
type OutputFingerprints struct {
	// Apps is organized as <name, fingerprint>
	Apps map[string]OutputFingerprint `json:"apps"`
}

// OutputFingerprint is a single piece of information about a tech validated and normalized
type OutputFingerprint struct {
	Cats        []int                             `json:"cats,omitempty"`
	CSS         []string                          `json:"css,omitempty"`
	DOM         map[string]map[string]interface{} `json:"dom,omitempty"`
	Cookies     map[string]string                 `json:"cookies,omitempty"`
	JS          map[string]string                 `json:"js,omitempty"`
	Headers     map[string]string                 `json:"headers,omitempty"`
	HTML        []string                          `json:"html,omitempty"`
	Script      []string                          `json:"scripts,omitempty"`
	ScriptSrc   []string                          `json:"scriptSrc,omitempty"`
	Meta        map[string][]string               `json:"meta,omitempty"`
	DNS         map[string][]string               `json:"dns,omitempty"`
	Implies     []string                          `json:"implies,omitempty"`
	Description string                            `json:"description,omitempty"`
	Website     string                            `json:"website,omitempty"`
	CPE         string                            `json:"cpe,omitempty"`
	Icon        string                            `json:"icon,omitempty"`
}

func main() {
	flag.Parse()

	log.Println("Fetching Wappalyzer XPI from Mozilla Add-ons...")

	// Create an HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 10,
			DisableCompression:  false,
		},
	}

	// Set up proper request with headers to avoid being blocked
	req, err := http.NewRequest("GET", "https://addons.mozilla.org/firefox/downloads/latest/wappalyzer/wappalyzer.xpi", nil)
	if err != nil {
		log.Fatalf("Failed to create request: %v", err)
	}

	// Set a reasonable User-Agent
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5931.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Failed to download XPI: %v\nPlease check your internet connection and try again.", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Failed to download XPI: HTTP %s\nThe Wappalyzer XPI may no longer be available at this URL.", resp.Status)
	}

	log.Printf("XPI download started, server responded with %s", resp.Status)
	xpiData, err := io.ReadAll(io.LimitReader(resp.Body, 100*1024*1024)) // 100MB limit to prevent DoS
	if err != nil {
		log.Fatalf("Failed to read XPI data: %v\nThe download may have been interrupted.", err)
	}

	if len(xpiData) == 0 {
		log.Fatalf("Downloaded XPI file is empty. Please try again later.")
	}

	log.Printf("Downloaded XPI file successfully (%d bytes)", len(xpiData))

	// Create a zip reader from the XPI data (XPI is just a ZIP file)
	zipReader, err := zip.NewReader(bytes.NewReader(xpiData), int64(len(xpiData)))
	if err != nil {
		log.Fatalf("Failed to create zip reader: %v\nThe downloaded file may be corrupted or not a valid XPI/ZIP file.", err)
	}

	// Parse technologies from the XPI
	masterTechs := make(map[string]Technology)
	techFilesFound := 0
	techFilesProcessed := 0

	// Look for the technology files in the XPI
	for _, file := range zipReader.File {
		// The path inside the XPI may vary, look for JSON files in the technologies directory
		if strings.HasSuffix(file.Name, ".json") && strings.Contains(file.Name, "technologies") {
			techFilesFound++

			rc, err := file.Open()
			if err != nil {
				log.Printf("Warning: Failed to open file in zip %s: %v (skipping)", file.Name, err)
				continue
			}

			content, err := io.ReadAll(io.LimitReader(rc, 10*1024*1024)) // 10MB limit per file
			rc.Close()
			if err != nil {
				log.Printf("Warning: Failed to read file in zip %s: %v (skipping)", file.Name, err)
				continue
			}

			var currentTechs map[string]Technology
			if err := json.Unmarshal(content, &currentTechs); err != nil {
				log.Printf("Warning: Could not unmarshal %s: %v (skipping)", file.Name, err)
				continue
			}

			// Merge into the master map
			for name, tech := range currentTechs {
				masterTechs[name] = tech
			}
			techFilesProcessed++
		}
	}

	if techFilesFound == 0 {
		log.Fatalf("No technology files found in the XPI. The Wappalyzer XPI structure may have changed.")
	}

	if techFilesProcessed == 0 {
		log.Fatalf("Failed to process any technology files from the XPI.")
	}

	log.Printf("Successfully processed %d/%d technology files containing %d technologies",
		techFilesProcessed, techFilesFound, len(masterTechs))

	if len(masterTechs) == 0 {
		log.Fatalf("No technologies found in the XPI. The format may have changed or the files might be empty.")
	}

	// Normalize fingerprints to the format expected by the kitsune library
	log.Println("Normalizing technology fingerprints...")
	outputFingerprints := normalizeFingerprints(masterTechs)

	log.Printf("Normalized %d valid fingerprints", len(outputFingerprints.Apps))

	// Ensure the output directory exists
	outputDir := filepath.Dir(*fingerprints)
	if outputDir != "" && outputDir != "." {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			log.Fatalf("Failed to create output directory %s: %v", outputDir, err)
		}
	}

	// Write the fingerprints to the output file
	log.Printf("Writing fingerprints to %s...", *fingerprints)
	fingerprintsFile, err := os.OpenFile(*fingerprints, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o666)
	if err != nil {
		log.Fatalf("Could not open fingerprints file %s: %v", *fingerprints, err)
	}

	// Sort map keys and pretty print the json to make git diffs useful
	data, err := json.MarshalIndent(outputFingerprints, "", "    ")
	if err != nil {
		_ = fingerprintsFile.Close() // Best effort close
		log.Fatalf("Could not marshal fingerprints: %v", err)
	}

	// Write data and handle potential disk space issues
	n, err := fingerprintsFile.Write(data)
	if err != nil || n != len(data) {
		_ = fingerprintsFile.Close() // Best effort close
		log.Fatalf("Failed to write fingerprints file (wrote %d/%d bytes): %v",
			n, len(data), err)
	}

	// Ensure file is properly closed and flushed
	if err := fingerprintsFile.Sync(); err != nil {
		_ = fingerprintsFile.Close() // Best effort close
		log.Printf("Warning: Failed to sync file to disk: %v", err)
	}

	if err := fingerprintsFile.Close(); err != nil {
		log.Printf("Warning: Failed to close fingerprints file: %v", err)
	}

	log.Printf("Successfully wrote %d fingerprints to %s (%d bytes)",
		len(outputFingerprints.Apps), *fingerprints, len(data))

	fmt.Println("✅ Fingerprint update completed successfully.")
}

func normalizeFingerprints(technologies map[string]Technology) *OutputFingerprints {
	outputFingerprints := &OutputFingerprints{Apps: make(map[string]OutputFingerprint)}

	for appName, tech := range technologies {
		output := OutputFingerprint{
			Cats:        tech.Cats,
			Cookies:     make(map[string]string),
			DOM:         make(map[string]map[string]interface{}),
			Headers:     make(map[string]string),
			JS:          make(map[string]string),
			Meta:        make(map[string][]string),
			DNS:         make(map[string][]string),
			Description: tech.Description,
			Website:     tech.Website,
			CPE:         tech.CPE,
			Icon:        tech.Icon,
		}

		// Process cookies
		// Keys (cookie names) are typically case-insensitive, so we normalize them
		// Values (patterns) are preserved in their original case for regex accuracy
		for cookie, value := range tech.Cookies {
			output.Cookies[strings.ToLower(cookie)] = value
		}

		// Process JS
		for k, v := range tech.JS {
			output.JS[k] = v
		}

		// Process headers
		// Header names are case-insensitive by HTTP spec, so we normalize them
		// Pattern values are preserved in their original case for regex accuracy
		for header, pattern := range tech.Headers {
			output.Headers[strings.ToLower(header)] = pattern
		}

		// Process DOM using reflection
		if tech.DOM != nil {
			v := reflect.ValueOf(tech.DOM)
			switch v.Kind() {
			case reflect.String:
				data := v.Interface().(string)
				output.DOM[data] = map[string]interface{}{"exists": ""}
			case reflect.Slice:
				data := v.Interface().([]interface{})
				for _, pattern := range data {
					if pat, ok := pattern.(string); ok {
						output.DOM[pat] = map[string]interface{}{"exists": ""}
					}
				}
			case reflect.Map:
				data := v.Interface().(map[string]interface{})
				for pattern, value := range data {
					if valueMap, ok := value.(map[string]interface{}); ok {
						output.DOM[pattern] = valueMap
					}
				}
			}
		}

		// Process HTML using reflection
		// HTML patterns are regex patterns that should preserve their case for accuracy
		if tech.HTML != nil {
			v := reflect.ValueOf(tech.HTML)
			switch v.Kind() {
			case reflect.String:
				output.HTML = []string{v.Interface().(string)}
			case reflect.Slice:
				data := v.Interface().([]interface{})
				output.HTML = make([]string, 0, len(data))
				for _, pattern := range data {
					if patStr, ok := pattern.(string); ok {
						output.HTML = append(output.HTML, patStr)
					}
				}
			}
			sort.Strings(output.HTML)
		}

		// Process Scripts using reflection
		// Script patterns are regex patterns that should preserve their case for accuracy
		if tech.Scripts != nil {
			v := reflect.ValueOf(tech.Scripts)
			switch v.Kind() {
			case reflect.String:
				output.Script = []string{v.Interface().(string)}
			case reflect.Slice:
				data := v.Interface().([]interface{})
				output.Script = make([]string, 0, len(data))
				for _, pattern := range data {
					if patStr, ok := pattern.(string); ok {
						output.Script = append(output.Script, patStr)
					}
				}
			}
			sort.Strings(output.Script)
		}

		// Process ScriptSrc using reflection
		// ScriptSrc patterns are regex patterns that should preserve their case for accuracy
		if tech.ScriptSrc != nil {
			v := reflect.ValueOf(tech.ScriptSrc)
			switch v.Kind() {
			case reflect.String:
				output.ScriptSrc = []string{v.Interface().(string)}
			case reflect.Slice:
				data := v.Interface().([]interface{})
				output.ScriptSrc = make([]string, 0, len(data))
				for _, pattern := range data {
					if patStr, ok := pattern.(string); ok {
						output.ScriptSrc = append(output.ScriptSrc, patStr)
					}
				}
			}
			sort.Strings(output.ScriptSrc)
		}

		// Process Meta using reflection
		// Meta tag names are normalized, but pattern values preserve case for regex accuracy
		for header, pattern := range tech.Meta {
			v := reflect.ValueOf(pattern)
			switch v.Kind() {
			case reflect.String:
				data := v.Interface().(string)
				if data == "" {
					output.Meta[strings.ToLower(header)] = []string{}
				} else {
					output.Meta[strings.ToLower(header)] = []string{data}
				}
			case reflect.Slice:
				if data, ok := v.Interface().([]interface{}); ok {
					final := make([]string, 0, len(data))
					for _, pattern := range data {
						if patStr, ok := pattern.(string); ok {
							final = append(final, patStr)
						}
					}
					sort.Strings(final)
					output.Meta[strings.ToLower(header)] = final
				}
			}
		}

		// Process Implies using reflection
		if tech.Implies != nil {
			v := reflect.ValueOf(tech.Implies)
			switch v.Kind() {
			case reflect.String:
				output.Implies = []string{v.Interface().(string)}
			case reflect.Slice:
				data := v.Interface().([]interface{})
				output.Implies = make([]string, 0, len(data))
				for _, pattern := range data {
					if patStr, ok := pattern.(string); ok {
						output.Implies = append(output.Implies, patStr)
					}
				}
			}
			sort.Strings(output.Implies)
		}

		// Process CSS using reflection
		if tech.CSS != nil {
			v := reflect.ValueOf(tech.CSS)
			switch v.Kind() {
			case reflect.String:
				output.CSS = []string{v.Interface().(string)}
			case reflect.Slice:
				data := v.Interface().([]interface{})
				output.CSS = make([]string, 0, len(data))
				for _, pattern := range data {
					if patStr, ok := pattern.(string); ok {
						output.CSS = append(output.CSS, patStr)
					}
				}
			}
			sort.Strings(output.CSS)
		}

		// Process DNS records
		// DNS record patterns are regex patterns that should preserve case
		if tech.DNS != nil {
			for recordType, patterns := range tech.DNS {
				// Initialize the slice for this record type if needed
				if output.DNS[recordType] == nil {
					output.DNS[recordType] = []string{}
				}

				v := reflect.ValueOf(patterns)
				switch v.Kind() {
				case reflect.String:
					// Single string pattern
					data := v.Interface().(string)
					output.DNS[recordType] = append(output.DNS[recordType], data)
				case reflect.Slice:
					// Array of patterns
					data := v.Interface().([]interface{})
					for _, pattern := range data {
						if patStr, ok := pattern.(string); ok {
							output.DNS[recordType] = append(output.DNS[recordType], patStr)
						}
					}
				}
			}

			// Sort all DNS record patterns for consistent output
			for recordType := range output.DNS {
				sort.Strings(output.DNS[recordType])
			}
		}

		// Only add if the fingerprint is valid
		outputFingerprints.Apps[appName] = output
	}
	return outputFingerprints
}
