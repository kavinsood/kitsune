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

	// Google tag containers (see gtm.go): the keys of those fetched, how
	// many were found in the page rather than linked as scripts, and what
	// they are matched by.
	gtmKeys       map[string]bool
	gtmDiscovered int
	gtm           []*gtmEvidence
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
		gtmKeys:    make(map[string]bool),
	}
}

// Start launches the asset fetcher pipeline
// It spawns the main consumer goroutine that processes incoming URLs
func (af *AssetFetcher) Start() {
	go func() {
		for assetURL := range af.urlChan {
			// Create a worker goroutine for each URL. AddURL has
			// already counted it in wg.
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
	if assetType == "script" {
		if key := googleTagKey(url); key != "" {
			af.addGoogleTag(url, key, false)
			return
		}
	}
	// Count the URL in wg before handing it over, so that a Wait after
	// Stop can't return before it is fetched.
	af.wg.Add(1)
	select {
	case af.urlChan <- AssetURL{URL: url, Type: assetType, Priority: priority}:
		// URL was added successfully
	case <-af.ctx.Done():
		// Context was cancelled, don't add more URLs
		af.wg.Done()
	}
}

// AddGTMContainer fetches the GTM container with the given id, found in the
// page, unless it is already fetched or maxGTMContainers have been.
func (af *AssetFetcher) AddGTMContainer(id string) {
	af.addGoogleTag(gtmContainerURL(id), "gtm.js?id="+id, true)
}

// addGoogleTag fetches the Google tag container at rawURL as a "gtm" asset,
// once per key. Containers don't go through urlChan, so they can be added
// at any time before wg is waited on, even after Stop.
func (af *AssetFetcher) addGoogleTag(rawURL, key string, discovered bool) {
	af.mutex.Lock()
	if af.gtmKeys[key] || discovered && af.gtmDiscovered >= maxGTMContainers {
		af.mutex.Unlock()
		return
	}
	af.gtmKeys[key] = true
	if discovered {
		af.gtmDiscovered++
	}
	af.mutex.Unlock()
	if af.ctx.Err() != nil {
		return
	}
	// Count it before starting it, so a Wait can't return first.
	af.wg.Add(1)
	go af.processURL(AssetURL{URL: rawURL, Type: "gtm", Priority: 5})
}

// GTMEvidence returns what the fetched containers are matched by. Call it
// after wg is waited on.
func (af *AssetFetcher) GTMEvidence() []*gtmEvidence {
	af.mutex.Lock()
	defer af.mutex.Unlock()
	return af.gtm
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
	if assetURL.Type == "script" || assetURL.Type == "gtm" {
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
	case "gtm":
		af.handleGTMResponse(resp)
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
	content, err := readString(resp, 1024*1024) // 1MB limit
	if err != nil {
		return
	}

	// Store the result
	af.mutex.Lock()
	(*af.jsContent)[originalURL] = content
	af.mutex.Unlock()
}

// handleGTMResponse reads the configuration of a Google tag container.
func (af *AssetFetcher) handleGTMResponse(resp *http.Response) {
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), "javascript") {
		return
	}
	c, err := readGTMContainer(resp.Body)
	if err != nil {
		return
	}
	ev := c.evidence()
	af.mutex.Lock()
	af.gtm = append(af.gtm, ev)
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
	content, err := readString(resp, 1024*1024) // 1MB limit
	if err != nil {
		return
	}

	// Store the result
	af.mutex.Lock()
	(*af.cssContent)[originalURL] = content
	af.mutex.Unlock()
}

// SetDNSRecords stores DNS records found through lookup
func (af *AssetFetcher) SetDNSRecords(records map[string][]string) {
	af.mutex.Lock()
	defer af.mutex.Unlock()
	af.dnsRecords = records
}

// readString reads at most limit bytes of resp's body into a string. Like
// io.ReadAll it reads into growing chunks and then assembles an exactly-sized
// result, but it builds the string directly, so the body isn't copied a
// second time by string(...).
func readString(resp *http.Response, limit int64) (string, error) {
	r := io.LimitReader(resp.Body, limit)
	next := int64(512)
	if resp.ContentLength > 0 {
		next = min(resp.ContentLength+1, limit+1) // +1 to see EOF in one read
	}
	var chunks [][]byte
	size := 0
	for {
		chunk := make([]byte, next)
		n, err := io.ReadFull(r, chunk)
		chunks = append(chunks, chunk[:n])
		size += n
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return "", err
		}
		next += next / 2
	}
	var sb strings.Builder
	sb.Grow(size)
	for _, chunk := range chunks {
		sb.Write(chunk)
	}
	return sb.String(), nil
}
