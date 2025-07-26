// kitsune/kitsune.go

package kitsune

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/kavinsood/kitsune/internal/pipeline"
)

//go:embed categories_data.json fingerprints_data.json
var embeddedFS embed.FS

// HTTPDoer is an interface satisfied by *http.Client and compatible clients.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
	Get(url string) (*http.Response, error)
}

// Kitsune is a client for working with tech detection
type Kitsune struct {
	apps           map[string]*pipeline.Fingerprint
	matcher        *EfficientMatcher
	httpClient     HTTPDoer
	certInfoCache  *sync.Map
	RegexTimeout   time.Duration
	RequestTimeout time.Duration
}

// AppFingerprint is an alias for the pipeline's Fingerprint struct for external use.
type AppFingerprint = pipeline.Fingerprint

// New creates a new Kitsune tech detection instance. If client is nil, a default HTTP client is used.
func New(client HTTPDoer) (*Kitsune, error) {
	// Load categories
	var err error
	categoryMap, err = loadCategories()
	if err != nil {
		return nil, fmt.Errorf("failed to load categories: %w", err)
	}

	certCache := &sync.Map{}
	k := &Kitsune{
		apps:           make(map[string]*pipeline.Fingerprint),
		certInfoCache:  certCache,
		RegexTimeout:   100 * time.Millisecond,
		RequestTimeout: 10 * time.Second, // Add a request timeout
	}

	if client == nil {
		// Configure the custom HTTP client for extracting TLS cert info
		k.httpClient = &http.Client{
			Timeout: k.RequestTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // We do our own verification in the callback
					VerifyConnection: func(cs tls.ConnectionState) error {
						// Default verification
						opts := x509.VerifyOptions{
							DNSName:       cs.ServerName,
							Intermediates: x509.NewCertPool(),
						}
						for _, cert := range cs.PeerCertificates[1:] {
							opts.Intermediates.AddCert(cert)
						}
						_, err := cs.PeerCertificates[0].Verify(opts)
						if err != nil {
							// Don't fail the connection, just log the error if needed.
							// log.Printf("Certificate verification failed for %s: %v", cs.ServerName, err)
						}

						// Extract and cache the issuer info
						if len(cs.PeerCertificates) > 0 {
							cert := cs.PeerCertificates[0]
							// Simple way to get a string representation of the issuer
							issuerStr := cert.Issuer.String()
							k.certInfoCache.Store(cs.ServerName, issuerStr)
						}
						return nil
					},
				},
			},
		}
	} else {
		k.httpClient = client
	}

	// Load fingerprints from embedded data
	fpBytes, err := embeddedFS.ReadFile("fingerprints_data.json")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded fingerprints: %w", err)
	}
	if err := k.loadFingerprintsFromBytes(fpBytes); err != nil {
		return nil, err
	}

	k.BuildEfficientMatcher()
	return k, nil
}

func (k *Kitsune) loadFingerprintsFromBytes(data []byte) error {
	type raw struct {
		Apps map[string]*pipeline.Fingerprint `json:"apps"`
	}
	var r raw
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}
	k.apps = r.Apps
	return nil
}

// AnalysisError holds errors from the concurrent data fetching stage.
type AnalysisError struct {
	MainPageErr error
	RobotsErr   error
	DNSErr      error
	// Add other fetch errors here as needed
}

// Error combines the collected errors into a single, readable string.
func (e *AnalysisError) Error() string {
	var errs []string
	if e.MainPageErr != nil {
		errs = append(errs, fmt.Sprintf("main page fetch failed: %v", e.MainPageErr))
	}
	if e.DNSErr != nil {
		errs = append(errs, fmt.Sprintf("dns lookup failed: %v", e.DNSErr))
	}
	if e.RobotsErr != nil {
		errs = append(errs, fmt.Sprintf("robots.txt fetch failed: %v", e.RobotsErr))
	}
	if len(errs) == 0 {
		return ""
	}
	return fmt.Sprintf("analysis failed: %s", strings.Join(errs, "; "))
}

// IsFatal returns true if a critical error occurred that should stop the analysis.
func (e *AnalysisError) IsFatal() bool {
	return e.MainPageErr != nil || e.DNSErr != nil
}

// FingerprintURL is the new main entry point for analysis.
func (k *Kitsune) FingerprintURL(targetUrl string) (map[string]Detection, error) {
	analysisData := &AnalysisData{
		TargetURL:  targetUrl,
		DNSRecords: make(map[string][]string),
	}
	var wg sync.WaitGroup

	type fetchResult struct {
		kind string // "main", "robots", "dns"
		err  error
	}
	errChan := make(chan fetchResult, 3) // One for each goroutine

	// --- Concurrent Data Gathering ---

	// 1. Fetch main page (this also populates cert cache)
	wg.Add(1)
	go func() {
		defer wg.Done()
		resp, err := k.httpClient.Get(targetUrl)
		if err != nil {
			errChan <- fetchResult{kind: "main", err: err}
			return
		}
		defer resp.Body.Close()
		analysisData.MainResponse = resp
		body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB limit
		if err == nil {
			analysisData.Body = body
		}
		errChan <- fetchResult{kind: "main", err: nil}
	}()

	// 2. Fetch robots.txt
	wg.Add(1)
	go func() {
		defer wg.Done()
		robotsURL, err := url.Parse(targetUrl)
		if err != nil {
			errChan <- fetchResult{kind: "robots", err: err}
			return
		}
		robotsURL.Path = "/robots.txt"
		resp, err := k.httpClient.Get(robotsURL.String())
		if err == nil && resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()
			content, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024)) // 1MB limit
			if err == nil {
				analysisData.RobotsContent = content
			}
		}
		// Only treat as error if the fetch itself failed (not if robots.txt is missing)
		if err != nil {
			errChan <- fetchResult{kind: "robots", err: err}
		} else {
			errChan <- fetchResult{kind: "robots", err: nil}
		}
	}()

	// 3. Perform DNS lookups
	wg.Add(1)
	go func() {
		defer wg.Done()
		parsedURL, err := url.Parse(targetUrl)
		if err != nil {
			errChan <- fetchResult{kind: "dns", err: err}
			return
		}
		host := parsedURL.Hostname()
		txtRecords, txtErr := net.LookupTXT(host)
		analysisData.DNSRecords["TXT"] = txtRecords
		mxRecords, mxErr := net.LookupMX(host)
		var mxStr []string
		for _, mx := range mxRecords {
			mxStr = append(mxStr, mx.Host)
		}
		analysisData.DNSRecords["MX"] = mxStr
		if txtErr != nil && mxErr != nil {
			errChan <- fetchResult{kind: "dns", err: txtErr} // Just report one
		} else {
			errChan <- fetchResult{kind: "dns", err: nil}
		}
	}()

	wg.Wait()
	close(errChan)

	// --- Error aggregation ---
	analysisErr := &AnalysisError{}
	for res := range errChan {
		if res.err != nil {
			switch res.kind {
			case "main":
				analysisErr.MainPageErr = res.err
			case "robots":
				analysisErr.RobotsErr = res.err
			case "dns":
				analysisErr.DNSErr = res.err
			}
		}
	}

	if analysisErr.IsFatal() {
		return nil, analysisErr
	}

	// --- Post-fetch processing ---

	// Retrieve cert issuer from cache
	parsedURL, err := url.Parse(targetUrl)
	if err == nil {
		if val, ok := k.certInfoCache.Load(parsedURL.Hostname()); ok {
			analysisData.CertIssuer = val.(string)
		}
	}

	// Parse DOM from body
	if analysisData.Body != nil {
		analysisData.PageData = collectDataFromDOM(analysisData.Body)
	}

	detected := make(map[string]Detection)
	runAllMatchers(k, analysisData, detected)

	// --- Implies Engine ---
	k.runImpliesEngine(detected)

	// Return non-fatal errors as well for caller inspection
	if analysisErr.RobotsErr != nil {
		return detected, analysisErr
	}

	return detected, nil
}

func (k *Kitsune) runImpliesEngine(detected map[string]Detection) {
	queue := make([]string, 0, len(detected))
	for tech := range detected {
		queue = append(queue, tech)
	}

	processed := make(map[string]bool)
	for len(queue) > 0 {
		techName := queue[0]
		queue = queue[1:]

		if processed[techName] {
			continue
		}
		processed[techName] = true

		// --- THIS IS THE GATE ---
		// Only trigger implications from high-confidence detections.
		sourceDetection, ok := detected[techName]
		if !ok || sourceDetection.Confidence < ConfidenceHigh {
			continue
		}

		if app, ok := k.apps[techName]; ok {
			for _, impliedTech := range app.Implies {
				if _, alreadyDetected := detected[impliedTech]; !alreadyDetected {
					detected[impliedTech] = Detection{
						DetectedBy: "implies from: " + techName,
						Confidence: ConfidenceMedium, // Implied detections are not as strong as the source.
					}
					queue = append(queue, impliedTech)
				}
			}
		}
	}
}

// BuildEfficientMatcher constructs the context-centric EfficientMatcher.
func (k *Kitsune) BuildEfficientMatcher() {
	matcher := &EfficientMatcher{
		HTMLPatterns:       []PatternInfo{},
		ScriptSrcPatterns:  []PatternInfo{},
		HeaderPatterns:     make(map[string][]PatternInfo),
		CookiePatterns:     make(map[string][]PatternInfo),
		MetaPatterns:       make(map[string][]PatternInfo),
		ScriptPatterns:     []PatternInfo{},
		JSPatterns:         make(map[string][]PatternInfo),
		CSSPatterns:        []PatternInfo{},
		URLPatterns:        []PatternInfo{},
		RobotsPatterns:     []PatternInfo{},
		DOMPatterns:        []PatternInfo{},
		DNSPatterns:        make(map[string][]PatternInfo),
		CertIssuerPatterns: make(map[string][]PatternInfo),
	}

	for appName, af := range k.apps {
		// HTML
		for _, pat := range af.HTML {
			if re, err := regexp.Compile("(?i)" + pat.Regex); err == nil {
				matcher.HTMLPatterns = append(matcher.HTMLPatterns, PatternInfo{Pattern: re, AppName: appName, Commands: pat.Commands})
			}
		}
		// ScriptSrc
		for _, pat := range af.ScriptSrc {
			if re, err := regexp.Compile("(?i)" + pat.Regex); err == nil {
				matcher.ScriptSrcPatterns = append(matcher.ScriptSrcPatterns, PatternInfo{Pattern: re, AppName: appName, Commands: pat.Commands})
			}
		}
		// Script
		for _, pat := range af.Script {
			if re, err := regexp.Compile("(?i)" + pat.Regex); err == nil {
				matcher.ScriptPatterns = append(matcher.ScriptPatterns, PatternInfo{Pattern: re, AppName: appName, Commands: pat.Commands})
			}
		}
		// CSS
		for _, pat := range af.CSS {
			if re, err := regexp.Compile("(?i)" + pat.Regex); err == nil {
				matcher.CSSPatterns = append(matcher.CSSPatterns, PatternInfo{Pattern: re, AppName: appName, Commands: pat.Commands})
			}
		}
		// Cookies
		for cookie, pat := range af.Cookies {
			if re, err := regexp.Compile("(?i)" + pat.Regex); err == nil {
				c := strings.ToLower(cookie)
				matcher.CookiePatterns[c] = append(matcher.CookiePatterns[c], PatternInfo{Pattern: re, AppName: appName, Commands: pat.Commands})
			}
		}
		// Headers
		for header, pat := range af.Headers {
			if re, err := regexp.Compile("(?i)" + pat.Regex); err == nil {
				h := strings.ToLower(header)
				matcher.HeaderPatterns[h] = append(matcher.HeaderPatterns[h], PatternInfo{Pattern: re, AppName: appName, Commands: pat.Commands})
			}
		}
		// Meta
		for meta, pats := range af.Meta {
			m := strings.ToLower(meta)
			for _, pat := range pats {
				if re, err := regexp.Compile("(?i)" + pat.Regex); err == nil {
					matcher.MetaPatterns[m] = append(matcher.MetaPatterns[m], PatternInfo{Pattern: re, AppName: appName, Commands: pat.Commands})
				}
			}
		}
		// JS
		for jsvar, pat := range af.JS {
			if re, err := regexp.Compile("(?i)" + pat.Regex); err == nil {
				matcher.JSPatterns[jsvar] = append(matcher.JSPatterns[jsvar], PatternInfo{Pattern: re, AppName: appName, Commands: pat.Commands})
			}
		}
		// --- New fields ---
		for _, pat := range af.URL {
			if re, err := regexp.Compile("(?i)" + pat.Regex); err == nil {
				matcher.URLPatterns = append(matcher.URLPatterns, PatternInfo{Pattern: re, AppName: appName, Commands: pat.Commands})
			}
		}
		for _, pat := range af.Robots {
			if re, err := regexp.Compile("(?i)" + pat.Regex); err == nil {
				matcher.RobotsPatterns = append(matcher.RobotsPatterns, PatternInfo{Pattern: re, AppName: appName, Commands: pat.Commands})
			}
		}
		// DOM
		// Define a denylist of generic tags that are useless as selectors on their own.
		domTagDenylist := map[string]struct{}{
			"a": {}, "body": {}, "div": {}, "span": {}, "p": {}, "script": {}, "style": {},
			"link": {}, "head": {}, "title": {}, "footer": {}, "header": {}, "main": {},
		}

		for _, pat := range af.DOM {
			selector := pat.Regex // Remember, for DOM patterns, the regex is a CSS selector.

			// --- NEW: Apply quality gates to the selector ---

			// Gate 1: Check if the selector is just a denied generic tag.
			if _, isDenied := domTagDenylist[selector]; isDenied {
				continue // Reject the pattern.
			}

			// Gate 2: Check for a specificity character. This is a powerful filter.
			if !strings.ContainsAny(selector, ".#[") {
				continue // Reject the pattern.
			}

			// Gate 3: The original compile check (though less important for selectors).
			if re, err := regexp.Compile(selector); err == nil {
				matcher.DOMPatterns = append(matcher.DOMPatterns, PatternInfo{Pattern: re, AppName: appName, Commands: pat.Commands})
			}
		}
		for key, pat := range af.DNS {
			if re, err := regexp.Compile("(?i)" + pat.Regex); err == nil {
				matcher.DNSPatterns[key] = append(matcher.DNSPatterns[key], PatternInfo{Pattern: re, AppName: appName, Commands: pat.Commands})
			}
		}
		for key, pat := range af.CertIssuer {
			if re, err := regexp.Compile("(?i)" + pat.Regex); err == nil {
				matcher.CertIssuerPatterns[key] = append(matcher.CertIssuerPatterns[key], PatternInfo{Pattern: re, AppName: appName, Commands: pat.Commands})
			}
		}
	}
	k.matcher = matcher
}

// Add back loadCategories helper for category loading
// CategoryItem represents a single category from categories_data.json
// Only the fields we care about for mapping (name)
type CategoryItem struct {
	Name string `json:"name"`
}

// categoryMap holds the mapping from category ID to name
var categoryMap map[int]string

// loadCategories parses the embedded categories_data.json and returns the category map
func loadCategories() (map[int]string, error) {
	data, err := embeddedFS.ReadFile("categories_data.json")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded categories_data.json: %w", err)
	}
	var raw map[string]CategoryItem
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse embedded categories_data.json: %w", err)
	}
	categoryMap := make(map[int]string, len(raw))
	for k, v := range raw {
		// Convert string key to int
		var id int
		if _, err := fmt.Sscanf(k, "%d", &id); err == nil {
			categoryMap[id] = v.Name
		}
	}
	return categoryMap, nil
}

// Add back collectDataFromDOM for DOM extraction
func collectDataFromDOM(body []byte) *PageData {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return &PageData{
			ScriptSrcs:    nil,
			MetaContent:   make(map[string][]string),
			InlineScripts: nil,
			InlineCSS:     nil,
			VisibleText:   "",
			Title:         "",
			RawBody:       body,
			GoQueryDoc:    nil,
		}
	}
	pd := &PageData{
		ScriptSrcs:    []string{},
		MetaContent:   make(map[string][]string),
		InlineScripts: []string{},
		InlineCSS:     []string{},
		VisibleText:   "",
		Title:         "",
		RawBody:       body,
		GoQueryDoc:    doc,
	}

	// Extract <script src="...">
	doc.Find("script[src]").Each(func(i int, s *goquery.Selection) {
		if src, exists := s.Attr("src"); exists {
			pd.ScriptSrcs = append(pd.ScriptSrcs, src)
		}
	})

	// Extract inline <script>
	doc.Find("script:not([src])").Each(func(i int, s *goquery.Selection) {
		pd.InlineScripts = append(pd.InlineScripts, s.Text())
	})

	// Extract inline <style>
	doc.Find("style").Each(func(i int, s *goquery.Selection) {
		pd.InlineCSS = append(pd.InlineCSS, s.Text())
	})

	// Extract <meta name=... content=...>
	doc.Find("meta").Each(func(i int, s *goquery.Selection) {
		var name, content string
		var hasName, hasContent bool

		// Check for 'name' attribute case-insensitively
		name, hasName = s.Attr("name")
		if !hasName {
			name, hasName = s.Attr("Name")
		}
		if !hasName {
			name, hasName = s.Attr("NAME")
		}

		// Check for 'content' attribute case-insensitively
		content, hasContent = s.Attr("content")
		if !hasContent {
			content, hasContent = s.Attr("Content")
		}

		if hasName && hasContent {
			pd.MetaContent[name] = append(pd.MetaContent[name], content)
		}
	})

	// Extract <title>
	title := doc.Find("title").First().Text()
	pd.Title = title

	// Extract visible text (excluding script, style, meta, noscript, title, head)
	var textBuf strings.Builder
	doc.Find("body").Each(func(i int, s *goquery.Selection) {
		s.Contents().Each(func(j int, n *goquery.Selection) {
			if goquery.NodeName(n) == "#text" {
				textBuf.WriteString(n.Text())
			}
		})
	})
	pd.VisibleText = textBuf.String()

	return pd
}

// CatsInfo contains basic information about an App's categories
// Now includes both IDs and names
type CatsInfo struct {
	Cats  []int
	Names []string
}

// GetCategories returns the categories for the detected technologies, including names
func (k *Kitsune) GetCategories(technologies map[string]Detection) map[string]CatsInfo {
	result := make(map[string]CatsInfo)
	for tech := range technologies {
		if af, ok := k.apps[tech]; ok {
			cats := af.Cats
			names := GetCategoryNames(cats)
			result[tech] = CatsInfo{Cats: cats, Names: names}
		}
	}
	return result
}

// GetAllCategories returns the full category ID->name map
func GetAllCategories() map[int]string {
	return categoryMap
}

// GetCategoryNames returns the human-readable names for a slice of category IDs
func GetCategoryNames(ids []int) []string {
	var names []string
	for _, id := range ids {
		if name, ok := categoryMap[id]; ok {
			names = append(names, name)
		}
	}
	return names
}

// NewFromFile creates a new Kitsune instance from a file
func NewFromFile(filePath string, loadEmbedded, supersede bool) (*Kitsune, error) {
	k := &Kitsune{
		apps:           make(map[string]*pipeline.Fingerprint),
		certInfoCache:  &sync.Map{},
		RegexTimeout:   100 * time.Millisecond,
		RequestTimeout: 10 * time.Second,
	}
	// Load categories
	var err error
	categoryMap, err = loadCategories()
	if err != nil {
		return nil, err
	}
	// Load fingerprints from file
	f, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	if err := k.loadFingerprintsFromBytes(f); err != nil {
		return nil, err
	}
	k.BuildEfficientMatcher()
	return k, nil
}

// Restore the legacy Fingerprint method for test compatibility
func (k *Kitsune) Fingerprint(headers http.Header, body []byte) (map[string]Detection, *PageData) {
	detected := make(map[string]Detection)
	pageData := collectDataFromDOM(body)
	// Simulate the old matcher flow: runAllMatchers with a partial AnalysisData
	analysisData := &AnalysisData{
		MainResponse: &http.Response{Header: headers},
		Body:         body,
		PageData:     pageData,
	}
	runAllMatchers(k, analysisData, detected)
	return detected, pageData
}
