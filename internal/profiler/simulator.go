package profiler

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"
)

// SimulateNetworkForKitsune runs a demonstration of the network parallelization capabilities
// of the technology detection engine
func SimulateNetworkForKitsune() {
	fmt.Println("=== Network Simulation Demo ===")
	fmt.Println("This demonstrates how the technology detection engine parallelizes network requests")
	fmt.Println()
	
	// Set up test parameters
	numScripts := 10
	numStylesheets := 5
	simulatedNetworkDelay := 100 * time.Millisecond

	// Create a mock server that serves the main page and resources with simulated delay
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate network delay
		time.Sleep(simulatedNetworkDelay)

		if r.URL.Path == "/" {
			// Serve the main HTML page with references to scripts and styles
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Server", "Kitsune Simulation")
			w.Header().Set("X-Powered-By", "Go")
			w.WriteHeader(http.StatusOK)

			// Create HTML with script and style references
			var html strings.Builder
			html.WriteString("<!DOCTYPE html><html><head><title>Network Simulation</title>")

			// Add script tags
			for i := 1; i <= numScripts; i++ {
				html.WriteString(fmt.Sprintf("<script src=\"/script%d.js\"></script>", i))
			}

			// Add style tags
			for i := 1; i <= numStylesheets; i++ {
				html.WriteString(fmt.Sprintf("<link rel=\"stylesheet\" href=\"/style%d.css\">", i))
			}

			html.WriteString("</head><body><div class=\"content\">Network Simulation Content</div></body></html>")
			io.WriteString(w, html.String())
		} else if strings.HasPrefix(r.URL.Path, "/script") {
			// Serve JavaScript with identifiable content
			w.Header().Set("Content-Type", "application/javascript")
			scriptNum := strings.TrimPrefix(r.URL.Path, "/script")
			scriptNum = strings.TrimSuffix(scriptNum, ".js")
			io.WriteString(w, fmt.Sprintf("/* Script %s */\nvar jQuery = {fn: {jquery: '3.6.0'}};\nvar angular = {version: {full: '1.8.2'}};\n", scriptNum))
		} else if strings.HasPrefix(r.URL.Path, "/style") {
			// Serve CSS with identifiable content
			w.Header().Set("Content-Type", "text/css")
			styleNum := strings.TrimPrefix(r.URL.Path, "/style")
			styleNum = strings.TrimSuffix(styleNum, ".css")
			io.WriteString(w, fmt.Sprintf("/* Style %s */\n.bootstrap-wrapper {}\n.mui-container {}\n", styleNum))
		}
	}))
	defer server.Close()

	fmt.Printf("Mock server running at %s\n", server.URL)
	fmt.Printf("- Serving %d scripts and %d stylesheets\n", numScripts, numStylesheets)
	fmt.Printf("- Simulated network delay: %s per request\n\n", simulatedNetworkDelay)
	fmt.Printf("- Sequential fetching would take at least: %s\n", 
		(time.Duration(numScripts+numStylesheets+1) * simulatedNetworkDelay))

	// Create a new client
	client, err := New()
	if err != nil {
		fmt.Printf("Error creating client: %v\n", err)
		return
	}

	// Make the request to the mock server
	fmt.Println("\nMaking request and analyzing with parallelized fetching...")
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

	// Run fingerprinting with URL to enable all features
	technologies := client.FingerprintWithURL(resp.Header, body, server.URL)

	elapsed := time.Since(startTime)
	fmt.Printf("Detection completed in %s\n", elapsed)
	fmt.Printf("Detected technologies: %v\n", technologies)
	
	fmt.Printf("\nParallelized performance gain: ~%dx faster\n", 
		int((time.Duration(numScripts+numStylesheets+1)*simulatedNetworkDelay)/elapsed))
}