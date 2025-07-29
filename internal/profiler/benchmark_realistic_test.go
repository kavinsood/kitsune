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

// RealisticBenchmark tests the performance with a realistic mock server
// that simulates actual network conditions
func BenchmarkRealistic(b *testing.B) {
	// Create a mock server with configurable latency
	latency := 100 * time.Millisecond // Simulate 100ms network latency
	
	// HTML content with references to multiple assets
	html := `
<!DOCTYPE html>
<html>
<head>
    <title>Test Page</title>
    <meta name="generator" content="WordPress 5.8" />
    <meta name="application-name" content="TestApp" />
    <link rel="stylesheet" href="/styles/main.css">
    <link rel="stylesheet" href="/styles/secondary.css">
    <script src="/scripts/jquery.js"></script>
    <script src="/scripts/analytics.js"></script>
    <script src="/scripts/app.js"></script>
</head>
<body>
    <div class="container">
        <h1>Test Page for Wappalyzer</h1>
    </div>
    <!-- Angular.js marker -->
    <div ng-app="testApp">
        <div ng-controller="TestController"></div>
    </div>
    <script>
        var appVersion = "1.2.3";
        angular.module('testApp', []);
    </script>
</body>
</html>
`

	// Start a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Apply simulated network latency
		time.Sleep(latency)
		
		// Set some technology-revealing headers
		w.Header().Set("Server", "nginx/1.19.0")
		w.Header().Set("X-Powered-By", "PHP/7.4.3")
		w.Header().Set("Set-Cookie", "wordpress_test=test; path=/")
		
		// Handle different paths
		switch {
		case r.URL.Path == "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(html))
			
		case r.URL.Path == "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("User-agent: *\nDisallow: /wp-admin/\n# WordPress"))
			
		case strings.HasPrefix(r.URL.Path, "/styles/"):
			w.Header().Set("Content-Type", "text/css")
			// CSS with technology hints
			w.Write([]byte(`.wp-block { display: block; } /* WordPress block */
.bootstrap-grid { display: grid; } /* Bootstrap hint */`))
			
		case strings.HasPrefix(r.URL.Path, "/scripts/"):
			w.Header().Set("Content-Type", "application/javascript")
			
			// Different JS content based on the file
			if strings.Contains(r.URL.Path, "jquery") {
				w.Write([]byte(`/*! jQuery v3.6.0 */
window.jQuery = { fn: { jquery: "3.6.0" } };`))
			} else if strings.Contains(r.URL.Path, "analytics") {
				w.Write([]byte(`(function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
(i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
})(window,document,'script','https://www.google-analytics.com/analytics.js','ga');`))
			} else {
				w.Write([]byte(`/* App JS */
var React = { version: "17.0.2" };
var Vue = { version: "2.6.14" };`))
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	
	// Server URL is already parsed
	
	// Create a wappalyzer client
	wappalyzer, err := New()
	if err != nil {
		b.Fatal(err)
	}
	
	// Make an initial request to get HTML content
	resp, err := http.Get(server.URL)
	if err != nil {
		b.Fatal(err)
	}
	defer resp.Body.Close()
	
	// Read the HTML content
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		b.Fatal(err)
	}
	
	// Convert response headers to map
	headersMap := make(map[string][]string)
	for k, v := range resp.Header {
		headersMap[k] = v
	}
	
	// Run benchmarks with different latencies
	for _, l := range []time.Duration{0, 50 * time.Millisecond, 100 * time.Millisecond} {
		latency = l
		
		// Benchmark original implementation
		b.Run(fmt.Sprintf("Original-Latency-%dms", l.Milliseconds()), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				wappalyzer.Fingerprint(headersMap, content)
			}
		})
		
		// Benchmark concurrent implementation with Response
		b.Run(fmt.Sprintf("Concurrent-Latency-%dms", l.Milliseconds()), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				wappalyzer.FingerprintWithResponse(resp, content)
			}
		})
		
		// Benchmark concurrent implementation with URL
		b.Run(fmt.Sprintf("ConcurrentURL-Latency-%dms", l.Milliseconds()), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				wappalyzer.FingerprintWithURL(headersMap, content, server.URL)
			}
		})
	}
}