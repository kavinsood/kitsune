package profiler

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestRealWorldPerformance provides a more accurate comparison of sequential vs concurrent
// approaches with simulated network latency
func TestRealWorldPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping real-world performance test in short mode")
	}

	// Set up variables for tracking performance
	var sequentialTime, concurrentTime time.Duration
	
	// Configure the test server's latency
	assetLatency := 100 * time.Millisecond
	
	// HTML content with references to multiple assets
	html := `
<!DOCTYPE html>
<html>
<head>
    <title>Test Page</title>
    <meta name="generator" content="WordPress 5.8" />
    <link rel="stylesheet" href="/styles/main.css">
    <link rel="stylesheet" href="/styles/theme.css">
    <script src="/scripts/jquery.js"></script>
    <script src="/scripts/react.js"></script>
    <script src="/scripts/vue.js"></script>
    <script src="/scripts/angular.js"></script>
    <script src="/scripts/app.js"></script>
</head>
<body>
    <div class="container">Content</div>
</body>
</html>
`

	// Start a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Apply latency to asset requests
		if r.URL.Path != "/" {
			time.Sleep(assetLatency)
		}
		
		// Set headers
		w.Header().Set("Server", "nginx/1.20.0")
		w.Header().Set("X-Powered-By", "PHP/7.4.3")
		
		// Handle different paths
		switch {
		case r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(html))
			
		case r.URL.Path == "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("User-agent: *\nDisallow: /wp-admin/"))
			
		case strings.HasPrefix(r.URL.Path, "/styles/"):
			w.Header().Set("Content-Type", "text/css")
			w.Write([]byte(".some-class { color: red; }"))
			
		case strings.HasPrefix(r.URL.Path, "/scripts/"):
			w.Header().Set("Content-Type", "application/javascript")
			// Add specific JS library signatures
			if strings.Contains(r.URL.Path, "jquery") {
				w.Write([]byte(`window.jQuery = {fn:{jquery:"3.6.0"}};`))
			} else if strings.Contains(r.URL.Path, "react") {
				w.Write([]byte(`window.React = {version:"17.0.2"};`))
			} else if strings.Contains(r.URL.Path, "vue") {
				w.Write([]byte(`window.Vue = {version:"2.6.14"};`))
			} else if strings.Contains(r.URL.Path, "angular") {
				w.Write([]byte(`window.angular = {version:{full:"1.8.2"}};`))
			} else {
				w.Write([]byte(`console.log('script loaded');`))
			}
		}
	}))
	defer server.Close()
	
	// Create a wappalyzer client
	wappalyzer, err := New()
	if err != nil {
		t.Fatal(err)
	}
	
	// Create HTTP client
	client := &http.Client{}
	
	// Run the sequential approach and measure time
	sequentialStart := time.Now()
	
	// First get main HTML
	resp, err := client.Get(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	
	// Convert response headers to map
	headers := make(map[string][]string)
	for k, v := range resp.Header {
		headers[k] = v
	}
	
	// Process headers and HTML (the base operation)
	sequentialTechs := wappalyzer.Fingerprint(headers, body)
	
	// Now sequentially fetch and process each asset
	// This simulates what would happen in a sequential implementation
	
	// Fetch robots.txt
	respRobots, err := client.Get(server.URL + "/robots.txt")
	if err == nil && respRobots.StatusCode == 200 {
		robotsBody, _ := io.ReadAll(respRobots.Body)
		_ = string(robotsBody) // Process robots.txt content
		respRobots.Body.Close()
	}
	
	// Fetch CSS files
	cssURLs := []string{"/styles/main.css", "/styles/theme.css"}
	for _, cssURL := range cssURLs {
		respCSS, err := client.Get(server.URL + cssURL)
		if err == nil {
			cssBody, _ := io.ReadAll(respCSS.Body)
			_ = string(cssBody) // Process CSS content
			respCSS.Body.Close()
		}
	}
	
	// Fetch JS files
	jsURLs := []string{
		"/scripts/jquery.js", 
		"/scripts/react.js", 
		"/scripts/vue.js", 
		"/scripts/angular.js", 
		"/scripts/app.js",
	}
	for _, jsURL := range jsURLs {
		respJS, err := client.Get(server.URL + jsURL)
		if err == nil {
			jsBody, _ := io.ReadAll(respJS.Body)
			_ = string(jsBody) // Process JS content
			respJS.Body.Close()
		}
	}
	
	sequentialTime = time.Since(sequentialStart)
	
	// Run the concurrent approach and measure time
	concurrentStart := time.Now()
	
	// Get a fresh response for the concurrent test
	respConcurrent, err := client.Get(server.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	bodyConcurrent, err := io.ReadAll(respConcurrent.Body)
	if err != nil {
		t.Fatal(err)
	}
	
	// Make sure the request URL is available
	respConcurrent.Request = &http.Request{
		URL: resp.Request.URL,
	}
	
	fmt.Println("Using URL:", respConcurrent.Request.URL.String())
	
	// Use the concurrent implementation that fetches all assets in parallel
	concurrentTechs := wappalyzer.FingerprintWithResponse(respConcurrent, bodyConcurrent)
	
	respConcurrent.Body.Close()
	concurrentTime = time.Since(concurrentStart)
	
	// Output results
	fmt.Printf("\nReal-world Performance Test Results (with %v asset latency):\n", assetLatency)
	fmt.Printf("  Sequential approach: %v\n", sequentialTime)
	fmt.Printf("  Concurrent approach: %v\n", concurrentTime)
	fmt.Printf("  Speedup: %.2fx\n", float64(sequentialTime)/float64(concurrentTime))
	
	fmt.Printf("\nSequential detected %d technologies\n", len(sequentialTechs))
	fmt.Printf("Concurrent detected %d technologies\n", len(concurrentTechs))
	
	// Make sure our test actually worked
	if len(sequentialTechs) == 0 || len(concurrentTechs) == 0 {
		t.Error("Failed to detect any technologies")
	}
}