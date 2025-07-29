package profiler

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// BenchmarkImplementationComparison compares the performance of different implementations
// with realistic network latency
func BenchmarkImplementationComparison(b *testing.B) {
	// Create a test server
	latencies := []time.Duration{10 * time.Millisecond, 50 * time.Millisecond, 100 * time.Millisecond}
	assetCount := 8
	
	for _, latency := range latencies {
		b.Run(fmt.Sprintf("Latency-%dms-Assets-%d", latency.Milliseconds(), assetCount), func(b *testing.B) {
			server := createTestServerWithLatency(latency, assetCount)
			defer server.Close()
			
			// Get the HTML content once
			resp, err := http.Get(server.URL)
			if err != nil {
				b.Fatal(err)
			}
			content, err := io.ReadAll(resp.Body)
			if err != nil {
				b.Fatal(err)
			}
			resp.Body.Close()
			
			// Create a wappalyzer client
			wappalyzer, err := New()
			if err != nil {
				b.Fatal(err)
			}
			
			// Run benchmarks for each implementation
			runImplementationBenchmarks(b, wappalyzer, server.URL, resp.Header, content)
		})
	}
}

// runImplementationBenchmarks benchmarks all three implementations
func runImplementationBenchmarks(b *testing.B, wappalyzer *Wappalyze, serverURL string, headers http.Header, content []byte) {
	headersMap := make(map[string][]string)
	for k, v := range headers {
		headersMap[k] = v
	}
	
	// Create a template response for testing
	templateResp := &http.Response{
		Header: headers,
		Request: &http.Request{
			URL: parseURL(serverURL),
		},
	}
	
	// Run benchmarks
	b.Run("Sequential", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			// Sequential would need to fetch all assets one by one
			// This is simulated by the existing benchmark
			wappalyzer.Fingerprint(headersMap, content)
		}
	})
	
	b.Run("Concurrent", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			// Create a fresh response object for each run
			resp := cloneResponse(templateResp)
			wappalyzer.FingerprintWithResponse(resp, content)
		}
	})
	
	b.Run("Pipeline", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			// Create a fresh response object for each run
			resp := cloneResponse(templateResp)
			wappalyzer.analyzeWithPipeline(resp, content)
		}
	})
}

// createTestServerWithLatency creates a test server with simulated network latency
func createTestServerWithLatency(latency time.Duration, assetCount int) *httptest.Server {
	// HTML content with references to multiple assets
	htmlTemplate := `
<!DOCTYPE html>
<html>
<head>
    <title>Test Page</title>
    <meta name="generator" content="WordPress 5.8" />
    %s
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
	
	// Generate link and script tags based on assetCount
	var tags strings.Builder
	scriptCount := assetCount / 2
	styleCount := assetCount - scriptCount
	
	for i := 0; i < styleCount; i++ {
		tags.WriteString(fmt.Sprintf(`<link rel="stylesheet" href="/styles/style%d.css">`, i))
		tags.WriteString("\n    ")
	}
	
	for i := 0; i < scriptCount; i++ {
		tags.WriteString(fmt.Sprintf(`<script src="/scripts/script%d.js"></script>`, i))
		tags.WriteString("\n    ")
	}
	
	html := fmt.Sprintf(htmlTemplate, tags.String())
	
	// Start a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Apply simulated network latency for assets
		if r.URL.Path != "/" {
			time.Sleep(latency)
		}
		
		// Set some technology-revealing headers
		w.Header().Set("Server", "nginx/1.19.0")
		w.Header().Set("X-Powered-By", "PHP/7.4.3")
		
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
			if strings.Contains(r.URL.Path, "script0") {
				w.Write([]byte(`/*! jQuery v3.6.0 */
window.jQuery = { fn: { jquery: "3.6.0" } };`))
			} else if strings.Contains(r.URL.Path, "script1") {
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
	
	return server
}

// Helper functions for benchmarking
func parseURL(urlStr string) *url.URL {
	u, _ := url.Parse(urlStr)
	return u
}

func cloneResponse(resp *http.Response) *http.Response {
	return &http.Response{
		Header: resp.Header,
		Request: &http.Request{
			URL: resp.Request.URL,
		},
	}
}