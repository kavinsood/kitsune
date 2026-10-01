package profiler

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

const (
	// maxAssetBytes is how much of a fetched script or stylesheet is read
	// and matched. Libraries can be anywhere in a bundle, but on Workers
	// reading 4MB instead of 1MB doubled the CPU time of heavy pages (and
	// added up to 1.5s) for one more library found in the truth set.
	maxAssetBytes = 1 << 20
	// maxFetchedBytes is how much is read of all the scripts and
	// stylesheets of a page together. It bounds the time spent matching
	// them and, as each is matched when it arrives and then dropped, the
	// memory they take.
	maxFetchedBytes = 16 << 20
	// maxScripts and maxStyles bound how many scripts and stylesheets are
	// fetched for a page, the first ones it links, so that a page linking
	// thousands of tiny assets can't turn a scan into thousands of
	// requests. Real pages link fewer (stripe.com, 77 scripts).
	maxScripts = 100
	maxStyles  = 20
	// maxPreloads bounds how many more scripts are fetched for a page
	// because it preloads them (see AddPreloads). Bundlers like Vite list
	// a page's chunks, bundled libraries included, only as preloads:
	// remix.run has 133, nuxt.com 142, allbirds.com 167.
	maxPreloads = 30
)

// sharedChunkNames are parts of file names that mark a preloaded chunk as
// likely shared, vendor or framework code, where bundled libraries are:
// vendor-x.js, chunk-vendors.x.js, framework-x.js, jsx-runtime-x.js,
// entry.client-x.js, _app-x.js, or index-x.js (Vite and Rollup name a
// shared chunk after its first module, often an index).
var sharedChunkNames = []string{
	"vendor", "framework", "react", "vue", "lib", "polyfill", "runtime",
	"shared", "common", "entry", "app", "main", "index",
}

// AssetURL represents an asset to be fetched with its type
type AssetURL struct {
	URL      string // The URL of the asset
	Type     string // "script" or "style"
	Priority int    // Not used for scheduling; preloads wait instead (see AddPreloads)
	preload  bool   // Fetched only because the page preloads it
}

// AssetFetcher manages concurrent fetching of external assets
// It provides a channel for receiving URLs and handles all network I/O
type AssetFetcher struct {
	baseURL    string                          // Base URL for resolving relative paths
	client     *http.Client                    // HTTP client for making requests
	ctx        context.Context                 // Context for cancellation/timeout
	wg         *sync.WaitGroup                 // WaitGroup for tracking goroutines
	urlChan    chan AssetURL                   // Channel for receiving asset URLs to fetch
	mutex      sync.Mutex                      // Mutex for protecting shared maps
	onAsset    func(assetType, content string) // Called with each fetched asset
	budget     atomic.Int64                    // Bytes left to read of all assets (maxFetchedBytes)
	maxWorkers int                             // Maximum concurrent requests
	semaphore  chan struct{}                   // Semaphore for limiting concurrent requests
	dnsRecords map[string][]string             // Results from DNS lookups
	added      map[string]bool                 // URLs added, guarded by mutex
	scripts    int                             // Scripts added, guarded by mutex
	styles     int                             // Stylesheets added, guarded by mutex
	waiting    sync.WaitGroup                  // Scripts and stylesheets added not yet holding a fetch slot

	// Google tag containers (see gtm.go): the keys of those fetched, how
	// many were found in the page rather than linked as scripts, and what
	// they are matched by.
	gtmKeys       map[string]bool
	gtmDiscovered int
	gtm           []*gtmEvidence
}

// NewAssetFetcher creates a new AssetFetcher instance. onAsset is called
// with the type ("script" or "style") and content of each asset fetched,
// concurrently and as soon as it is read, so that it can be matched and
// dropped while other assets are being fetched.
func NewAssetFetcher(baseURL string, ctx context.Context, wg *sync.WaitGroup, maxWorkers int, onAsset func(assetType, content string)) *AssetFetcher {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	af := &AssetFetcher{
		baseURL:    baseURL,
		client:     client,
		ctx:        ctx,
		wg:         wg,
		urlChan:    make(chan AssetURL, 50), // Buffered channel to avoid blocking
		onAsset:    onAsset,
		maxWorkers: maxWorkers,
		semaphore:  make(chan struct{}, maxWorkers),
		dnsRecords: make(map[string][]string),
		gtmKeys:    make(map[string]bool),
	}
	af.budget.Store(maxFetchedBytes)
	return af
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
	// A page may link an asset more than once; fetch it once.
	af.mutex.Lock()
	if af.added[url] || assetType == "script" && af.scripts >= maxScripts || assetType == "style" && af.styles >= maxStyles {
		af.mutex.Unlock()
		return
	}
	if af.added == nil {
		af.added = make(map[string]bool)
	}
	af.added[url] = true
	switch assetType {
	case "script":
		af.scripts++
	case "style":
		af.styles++
	}
	af.mutex.Unlock()
	// Count the URL in wg before handing it over, so that a Wait after
	// Stop can't return before it is fetched.
	af.wg.Add(1)
	af.waiting.Add(1)
	select {
	case af.urlChan <- AssetURL{URL: url, Type: assetType, Priority: priority}:
		// URL was added successfully
	case <-af.ctx.Done():
		// Context was cancelled, don't add more URLs
		af.waiting.Done()
		af.wg.Done()
	}
}

// AddPreloads fetches as scripts up to maxPreloads of urls, the scripts a
// page preloads in document order, chosen by selectPreloads among those
// not already added. Call it once, after all the page's scripts and
// stylesheets are added: the preloads only start once each of those holds
// a fetch slot (or is done), so they never delay them. Like containers
// they don't go through urlChan, so this can be called after Stop.
func (af *AssetFetcher) AddPreloads(urls []string) {
	var fresh, tags []string
	seen := make(map[string]bool)
	af.mutex.Lock()
	for _, u := range urls {
		if seen[u] || af.added[u] {
			continue
		}
		seen[u] = true
		if googleTagKey(u) != "" {
			tags = append(tags, u)
		} else {
			fresh = append(fresh, u)
		}
	}
	urls = selectPreloads(fresh, maxPreloads)
	if af.added == nil {
		af.added = make(map[string]bool)
	}
	for _, u := range urls {
		af.added[u] = true
	}
	af.mutex.Unlock()
	for _, u := range tags {
		af.addGoogleTag(u, googleTagKey(u), false)
	}
	if len(urls) == 0 || af.ctx.Err() != nil {
		return
	}
	af.wg.Add(len(urls))
	go func() {
		af.waiting.Wait()
		for _, u := range urls {
			go af.processURL(AssetURL{URL: u, Type: "script", Priority: 1, preload: true})
		}
	}()
}

// selectPreloads returns up to n of urls: first those that look like
// shared chunks (see sharedChunk), then the others, each in the order of
// urls.
func selectPreloads(urls []string, n int) []string {
	if len(urls) <= n {
		return urls
	}
	ranked := append([]string(nil), urls...)
	sort.SliceStable(ranked, func(i, j int) bool {
		return sharedChunk(ranked[i]) && !sharedChunk(ranked[j])
	})
	return ranked[:n]
}

// sharedChunk reports whether the file name of rawURL contains one of
// sharedChunkNames, ignoring case.
func sharedChunk(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	name := strings.ToLower(path.Base(u.Path))
	for _, s := range sharedChunkNames {
		if strings.Contains(name, s) {
			return true
		}
	}
	return false
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

// processURL fetches a single URL and hands its content to onAsset.
func (af *AssetFetcher) processURL(assetURL AssetURL) {
	defer af.wg.Done()
	// Match outside the semaphore, so the next fetch starts meanwhile.
	if content := af.fetch(assetURL); content != "" {
		af.onAsset(assetURL.Type, content)
	}
}

// fetch returns the content of an asset, or "" if it couldn't be fetched
// or isn't of the expected type. It holds a slot of the semaphore.
func (af *AssetFetcher) fetch(assetURL AssetURL) string {
	// Acquire semaphore to limit concurrency
	select {
	case af.semaphore <- struct{}{}:
		defer func() { <-af.semaphore }()
	case <-af.ctx.Done():
		af.doneWaiting(assetURL)
		return ""
	}
	af.doneWaiting(assetURL)
	// Containers are bounded by maxGTMBytes instead.
	if assetURL.Type != "gtm" && af.budget.Load() <= 0 {
		return ""
	}

	// Resolve relative URLs
	absoluteURL, err := af.resolveURL(assetURL.URL)
	if err != nil {
		return ""
	}

	// Create request with context
	req, err := http.NewRequestWithContext(af.ctx, "GET", absoluteURL, nil)
	if err != nil {
		return ""
	}

	// Add common headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5931.0 Safari/537.36")
	var types []string
	switch assetURL.Type {
	case "script", "gtm":
		req.Header.Set("Accept", "*/*")
		types = []string{"javascript", "text/plain"}
	case "style":
		req.Header.Set("Accept", "text/css,*/*;q=0.1")
		types = []string{"text/css", "text/plain"}
	default:
		return ""
	}

	resp, err := af.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	// Some servers misconfigure scripts and stylesheets as text/plain.
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, types[0]) && !strings.Contains(contentType, types[1]) {
		return ""
	}
	if assetURL.Type == "gtm" {
		af.handleGTMResponse(resp)
		return ""
	}
	// What was read before an error (a timeout in a large body) is
	// matched as well.
	content, _ := readString(resp, maxAssetBytes, &af.budget)
	return content
}

// doneWaiting marks a page's script or stylesheet as no longer waiting
// for a fetch slot, which preloads wait for.
func (af *AssetFetcher) doneWaiting(assetURL AssetURL) {
	if assetURL.Type != "gtm" && !assetURL.preload {
		af.waiting.Done()
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

// SetDNSRecords stores DNS records found through lookup
func (af *AssetFetcher) SetDNSRecords(records map[string][]string) {
	af.mutex.Lock()
	defer af.mutex.Unlock()
	af.dnsRecords = records
}

// readString reads resp's body into a string, up to limit bytes and as
// many as budget has left, which it takes from budget. If reading fails it
// returns what was read with the error. Like io.ReadAll it reads into
// growing chunks and then assembles an exactly-sized result, but it builds
// the string directly, and uses the chunk itself if there is only one, so
// the body isn't copied a second time by string(...).
func readString(resp *http.Response, limit int64, budget *atomic.Int64) (string, error) {
	next := int64(512)
	if resp.ContentLength > 0 {
		next = resp.ContentLength + 1 // +1 to see EOF in one read
	}
	var chunks [][]byte
	var size int64
	var err error
	for size < limit {
		n := takeBudget(budget, min(next, limit-size))
		if n == 0 {
			break
		}
		chunk := make([]byte, n)
		var m int
		m, err = io.ReadFull(resp.Body, chunk)
		budget.Add(n - int64(m))
		if m > 0 {
			chunks = append(chunks, chunk[:m])
			size += int64(m)
		}
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				err = nil
			}
			break
		}
		next += next / 2
	}
	if len(chunks) == 1 && cap(chunks[0])-len(chunks[0]) <= 512 {
		return unsafe.String(&chunks[0][0], len(chunks[0])), err
	}
	var sb strings.Builder
	sb.Grow(int(size))
	for _, chunk := range chunks {
		sb.Write(chunk)
	}
	return sb.String(), err
}

// takeBudget takes up to n bytes from budget, returning how many it took.
func takeBudget(budget *atomic.Int64, n int64) int64 {
	for {
		left := budget.Load()
		got := min(n, left)
		if got <= 0 {
			return 0
		}
		if budget.CompareAndSwap(left, left-got) {
			return got
		}
	}
}
