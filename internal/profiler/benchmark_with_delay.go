package profiler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

// SimulateNetwork demonstrates the performance difference between sequential and concurrent
// approaches to fetching multiple resources
func SimulateNetwork() {
	fmt.Println("\n=== Network I/O Simulation Benchmark ===")
	fmt.Println("This demonstrates why concurrency matters for I/O-bound operations")

	// Simulate network latency per request
	latency := 100 * time.Millisecond

	// Number of resources to fetch
	numResources := 8

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Apply latency to simulate network conditions
		time.Sleep(latency)

		// Send a simple response
		if strings.Contains(r.URL.Path, "js") {
			w.Header().Set("Content-Type", "application/javascript")
			w.Write([]byte("console.log('loaded');"))
		} else if strings.Contains(r.URL.Path, "css") {
			w.Header().Set("Content-Type", "text/css")
			w.Write([]byte(".class { color: red; }"))
		} else {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<html><body>Hello</body></html>"))
		}
	}))
	defer server.Close()

	client := &http.Client{}

	// Sequential approach
	fmt.Printf("\nSequential approach (with %v latency per request):\n", latency)
	sequentialStart := time.Now()

	for i := 0; i < numResources; i++ {
		url := fmt.Sprintf("%s/resource%d.%s", server.URL, i, map[int]string{
			0: "html",
			1: "js",
			2: "css",
			3: "js",
			4: "css",
			5: "js",
			6: "css",
			7: "js",
		}[i])

		resp, _ := client.Get(url)
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
	}

	sequentialTime := time.Since(sequentialStart)
	fmt.Printf("  Total time: %v\n", sequentialTime)

	// Concurrent approach
	fmt.Printf("\nConcurrent approach (with %v latency per request):\n", latency)
	concurrentStart := time.Now()

	var wg sync.WaitGroup
	for i := 0; i < numResources; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			url := fmt.Sprintf("%s/resource%d.%s", server.URL, i, map[int]string{
				0: "html",
				1: "js",
				2: "css",
				3: "js",
				4: "css",
				5: "js",
				6: "css",
				7: "js",
			}[i])

			resp, _ := client.Get(url)
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
		}(i)
	}

	wg.Wait()
	concurrentTime := time.Since(concurrentStart)
	fmt.Printf("  Total time: %v\n", concurrentTime)

	// Show comparison
	speedup := float64(sequentialTime) / float64(concurrentTime)
	fmt.Printf("\nComparison:\n")
	fmt.Printf("  Sequential: %v\n", sequentialTime)
	fmt.Printf("  Concurrent: %v\n", concurrentTime)
	fmt.Printf("  Speedup: %.2fx faster with concurrent approach\n", speedup)
	fmt.Printf("  Theory predicts: For %d requests with %v latency each:\n", numResources, latency)
	fmt.Printf("    - Sequential: ~%v (%d * %v)\n", time.Duration(numResources)*latency, numResources, latency)
	fmt.Printf("    - Concurrent: ~%v (max latency)\n", latency)

	fmt.Println("\nThis is why the concurrent implementation is better for real-world usage,")
	fmt.Println("even though benchmarks in local/test environments may show otherwise.")
}