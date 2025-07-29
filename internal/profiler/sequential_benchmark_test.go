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

// BenchmarkSequentialVsConcurrent compares sequential vs concurrent fetching
// with a more realistic test that actually performs network requests
func BenchmarkSequentialVsConcurrent(b *testing.B) {
	// Set latency for network requests
	latency := 50 * time.Millisecond
	
	// HTML content with references to multiple assets
	html := `
<!DOCTYPE html>
<html>
<head>
    <title>Test Page</title>
    <link rel="stylesheet" href="/styles/main.css">
    <link rel="stylesheet" href="/styles/theme.css">
    <script src="/scripts/jquery.js"></script>
    <script src="/scripts/app.js"></script>
    <script src="/scripts/analytics.js"></script>
</head>
<body>
    <div class="container">Content</div>
</body>
</html>
`

	// Start a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Apply configurable latency to simulate network
		time.Sleep(latency)
		
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
			w.Write([]byte("console.log('script loaded');"))
		}
	}))
	defer server.Close()
	
	// Create a wappalyzer client
	wappalyzer, err := New()
	if err != nil {
		b.Fatal(err)
	}
	
	// Create HTTP client
	client := &http.Client{}
	
	// Test with different latencies
	for _, l := range []time.Duration{10 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond} {
		latency = l
		
		b.Run(fmt.Sprintf("Sequential-Latency-%dms", l.Milliseconds()), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				// First get main HTML
				resp, _ := client.Get(server.URL + "/")
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				
				// Convert response headers to map
				headers := make(map[string][]string)
				for k, v := range resp.Header {
					headers[k] = v
				}
				
				// Process headers and HTML
				techs := wappalyzer.Fingerprint(headers, body)
				
				// Now sequentially fetch and process each asset
				// This simulates what the original implementation would need to do
				
				// Fetch robots.txt
				respRobots, _ := client.Get(server.URL + "/robots.txt")
				if respRobots.StatusCode == 200 {
					robotsBody, _ := io.ReadAll(respRobots.Body)
					_ = string(robotsBody) // Process robots.txt content
				}
				respRobots.Body.Close()
				
				// Fetch CSS files
				respCSS1, _ := client.Get(server.URL + "/styles/main.css")
				cssBody1, _ := io.ReadAll(respCSS1.Body)
				_ = string(cssBody1) // Process CSS content
				respCSS1.Body.Close()
				
				respCSS2, _ := client.Get(server.URL + "/styles/theme.css")
				cssBody2, _ := io.ReadAll(respCSS2.Body)
				_ = string(cssBody2) // Process CSS content
				respCSS2.Body.Close()
				
				// Fetch JS files
				respJS1, _ := client.Get(server.URL + "/scripts/jquery.js")
				jsBody1, _ := io.ReadAll(respJS1.Body)
				_ = string(jsBody1) // Process JS content
				respJS1.Body.Close()
				
				respJS2, _ := client.Get(server.URL + "/scripts/app.js")
				jsBody2, _ := io.ReadAll(respJS2.Body)
				_ = string(jsBody2) // Process JS content
				respJS2.Body.Close()
				
				respJS3, _ := client.Get(server.URL + "/scripts/analytics.js")
				jsBody3, _ := io.ReadAll(respJS3.Body)
				_ = string(jsBody3) // Process JS content
				respJS3.Body.Close()
				
				_ = techs // Use the result to prevent optimization
			}
		})
		
		b.Run(fmt.Sprintf("Concurrent-Latency-%dms", l.Milliseconds()), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				// Get main HTML first
				resp, _ := client.Get(server.URL + "/")
				body, _ := io.ReadAll(resp.Body)
				
				// Use the concurrent implementation that fetches all assets in parallel
				_ = wappalyzer.FingerprintWithResponse(resp, body)
				
				resp.Body.Close()
			}
		})
	}
}