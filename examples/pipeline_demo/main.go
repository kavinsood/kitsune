package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/kavinsood/kitsune/internal/profiler"
)

func main() {
	fmt.Println("=== Pipeline Architecture Demo ===")
	fmt.Println("This demonstrates the performance advantage of a true streaming pipeline")
	fmt.Println("for web page analysis with multiple external resources.")
	fmt.Println()

	// Set up test parameters
	numScripts := 5
	numStylesheets := 3
	simulatedNetworkDelay := 200 * time.Millisecond

	// Create a mock server that serves the main page and resources with simulated delay
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate network delay
		time.Sleep(simulatedNetworkDelay)

		if r.URL.Path == "/" {
			// Serve the main HTML page with references to scripts and styles
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Server", "Kitsune Pipeline Demo")
			w.Header().Set("X-Powered-By", "Go")
			w.WriteHeader(http.StatusOK)

			// Create HTML with script and style references
			var html strings.Builder
			html.WriteString("<!DOCTYPE html><html><head><title>Pipeline Demo</title>")

			// Add script tags
			for i := 1; i <= numScripts; i++ {
				html.WriteString(fmt.Sprintf("<script src=\"/script%d.js\"></script>", i))
			}

			// Add style tags
			for i := 1; i <= numStylesheets; i++ {
				html.WriteString(fmt.Sprintf("<link rel=\"stylesheet\" href=\"/style%d.css\">", i))
			}

			html.WriteString("</head><body><div class=\"content\">Pipeline Demo Content</div></body></html>")
			io.WriteString(w, html.String())
		} else if strings.HasPrefix(r.URL.Path, "/script") {
			// Serve JavaScript with identifiable content
			w.Header().Set("Content-Type", "application/javascript")
			scriptNum := strings.TrimPrefix(r.URL.Path, "/script")
			scriptNum = strings.TrimSuffix(scriptNum, ".js")
			io.WriteString(w, fmt.Sprintf("/* Script %s */\nvar React = {version: '17.0.2'};\nvar angular = {version: {full: '1.8.2'}};\n", scriptNum))
		} else if strings.HasPrefix(r.URL.Path, "/style") {
			// Serve CSS with identifiable content
			w.Header().Set("Content-Type", "text/css")
			styleNum := strings.TrimPrefix(r.URL.Path, "/style")
			styleNum = strings.TrimSuffix(styleNum, ".css")
			io.WriteString(w, fmt.Sprintf("/* Style %s */\n.bootstrap-wrapper {}\n.jquery-ui {}\n", styleNum))
		}
	}))
	defer server.Close()

	fmt.Printf("Mock server running at %s\n", server.URL)
	fmt.Printf("- Serving %d scripts and %d stylesheets\n", numScripts, numStylesheets)
	fmt.Printf("- Simulated network delay: %s per request\n\n", simulatedNetworkDelay)

	// Create a new profiler instance
	wapClient, err := profiler.New()
	if err != nil {
		fmt.Printf("Error creating client: %v\n", err)
		return
	}

	// Make the request to the mock server
	fmt.Println("Making request to server...")
	startTime := time.Now()

	resp, err := http.Get(server.URL)
	if err != nil {
		fmt.Printf("Error making request: %v\n", err)
		return
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		fmt.Printf("Error reading body: %v\n", err)
		return
	}

	// Run fingerprinting with the pipeline architecture
	fmt.Println("Running technology detection with pipeline architecture...")
	technologies := wapClient.FingerprintWithURL(resp.Header, body, server.URL)

	elapsed := time.Since(startTime)
	fmt.Printf("Detection completed in %s\n", elapsed)
	fmt.Printf("Detected technologies: %v\n", technologies)

	// For comparison, run again but with a fresh response to ensure fair timing
	resp, err = http.Get(server.URL)
	if err != nil {
		fmt.Printf("Error making second request: %v\n", err)
		return
	}

	// Read the response body
	body, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		fmt.Printf("Error reading body: %v\n", err)
		return
	}

	fmt.Println("\nDone!")
}