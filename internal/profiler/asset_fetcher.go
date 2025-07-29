package profiler

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// AssetURL represents an asset to be fetched with its type
type AssetURL struct {
	URL      string // The URL of the asset
	Type     string // "script" or "style"
	Priority int    // Priority for processing (higher numbers are processed first)
}

// AssetFetcher manages concurrent fetching of external assets
// It provides a channel for receiving URLs and handles all network I/O
type AssetFetcher struct {
	baseURL    string              // Base URL for resolving relative paths
	client     *http.Client        // HTTP client for making requests
	ctx        context.Context     // Context for cancellation/timeout
	wg         *sync.WaitGroup     // WaitGroup for tracking goroutines
	urlChan    chan AssetURL       // Channel for receiving asset URLs to fetch
	mutex      sync.Mutex          // Mutex for protecting shared maps
	jsContent  *map[string]string  // Pointer to map of JavaScript content by URL
	cssContent *map[string]string  // Pointer to map of CSS content by URL
	maxWorkers int                 // Maximum concurrent requests
	semaphore  chan struct{}       // Semaphore for limiting concurrent requests
	dnsRecords map[string][]string // Results from DNS lookups
}

// NewAssetFetcher creates a new AssetFetcher instance
func NewAssetFetcher(baseURL string, ctx context.Context, wg *sync.WaitGroup, maxWorkers int, jsContent *map[string]string, cssContent *map[string]string) *AssetFetcher {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	return &AssetFetcher{
		baseURL:    baseURL,
		client:     client,
		ctx:        ctx,
		wg:         wg,
		urlChan:    make(chan AssetURL, 50), // Buffered channel to avoid blocking
		jsContent:  jsContent,
		cssContent: cssContent,
		maxWorkers: maxWorkers,
		semaphore:  make(chan struct{}, maxWorkers),
		dnsRecords: make(map[string][]string),
	}
}

// Start launches the asset fetcher pipeline
// It spawns the main consumer goroutine that processes incoming URLs
func (af *AssetFetcher) Start() {
	go func() {
		for assetURL := range af.urlChan {
			// Create a worker goroutine for each URL
			af.wg.Add(1)
			go af.processURL(assetURL)
		}
	}()
}

// Stop signals that no more URLs will be sent
// This should be called after all URLs have been sent to the channel
func (af *AssetFetcher) Stop() {
	close(af.urlChan)
}

// AddURL adds an asset URL to be fetched
// This is a convenience method that can be used instead of sending directly to the channel
func (af *AssetFetcher) AddURL(url string, assetType string, priority int) {
	select {
	case af.urlChan <- AssetURL{URL: url, Type: assetType, Priority: priority}:
		// URL was added successfully
	case <-af.ctx.Done():
		// Context was cancelled, don't add more URLs
	}
}

// processURL handles fetching and processing of a single URL
func (af *AssetFetcher) processURL(assetURL AssetURL) {
	defer af.wg.Done()

	// Acquire semaphore to limit concurrency
	select {
	case af.semaphore <- struct{}{}:
		// Acquired semaphore
		defer func() { <-af.semaphore }()
	case <-af.ctx.Done():
		// Context cancelled while waiting for semaphore
		return
	}

	// Resolve relative URLs
	absoluteURL, err := af.resolveURL(assetURL.URL)
	if err != nil {
		return
	}

	// Create request with context
	req, err := http.NewRequestWithContext(af.ctx, "GET", absoluteURL, nil)
	if err != nil {
		return
	}

	// Add common headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5931.0 Safari/537.36")
	if assetURL.Type == "script" {
		req.Header.Set("Accept", "*/*")
	} else if assetURL.Type == "style" {
		req.Header.Set("Accept", "text/css,*/*;q=0.1")
	}

	// Make the request
	resp, err := af.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Handle different asset types
	switch assetURL.Type {
	case "script":
		af.handleScriptResponse(resp, assetURL.URL)
	case "style":
		af.handleStyleResponse(resp, assetURL.URL)
	}
}

// resolveURL converts a possibly relative URL to absolute
func (af *AssetFetcher) resolveURL(rawURL string) (string, error) {
	base, err := url.Parse(af.baseURL)
	if err != nil {
		return "", err
	}

	ref, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	return base.ResolveReference(ref).String(), nil
}

// handleScriptResponse processes a JavaScript response
func (af *AssetFetcher) handleScriptResponse(resp *http.Response, originalURL string) {
	// Check if we got a JS response
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "javascript") && !strings.Contains(contentType, "text/plain") {
		// Skip if not JavaScript content (but allow text/plain as some servers misconfigure JS)
		return
	}

	// Read the content with a limit to avoid huge files
	content, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
	if err != nil {
		return
	}

	// Store the result
	af.mutex.Lock()
	(*af.jsContent)[originalURL] = string(content)
	af.mutex.Unlock()
}

// handleStyleResponse processes a CSS response
func (af *AssetFetcher) handleStyleResponse(resp *http.Response, originalURL string) {
	// Check if we got a CSS response
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/css") && !strings.Contains(contentType, "text/plain") {
		// Skip if not CSS content (but allow text/plain as some servers misconfigure CSS)
		return
	}

	// Read the content with a limit to avoid huge files
	content, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
	if err != nil {
		return
	}

	// Store the result
	af.mutex.Lock()
	(*af.cssContent)[originalURL] = string(content)
	af.mutex.Unlock()
}

// SetDNSRecords stores DNS records found through lookup
func (af *AssetFetcher) SetDNSRecords(records map[string][]string) {
	af.mutex.Lock()
	defer af.mutex.Unlock()
	af.dnsRecords = records
}
