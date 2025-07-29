package profiler

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

// richResult contains all possible outputs from technology detection
type richResult struct {
	technologies map[string]struct{} // Detected technologies
	title        string              // Page title
	appInfo      map[string]AppInfo  // Application info
	categoryInfo map[string]CatsInfo // Category info
}

// GetTechnologies returns the detected technologies map
func (r richResult) GetTechnologies() map[string]struct{} {
	return r.technologies
}

// Wappalyze is a client for working with tech detection
type Wappalyze struct {
	original      *Fingerprints
	fingerprints  *CompiledFingerprints
	regexTimeout  time.Duration
	httpClient    *http.Client
	certInfoCache *sync.Map
}

// New creates a new tech detection instance
func New() (*Wappalyze, error) {
	wappalyze := &Wappalyze{
		fingerprints: &CompiledFingerprints{
			Apps:             make(map[string]*CompiledFingerprint),
			domPatternsByTag: make(map[string]map[string][]string),
		},
		regexTimeout:  100 * time.Millisecond, // A sensible default
		certInfoCache: &sync.Map{},
	}

	// Create the custom transport with the VerifyConnection callback
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Required because we are overriding verification
			VerifyConnection: func(cs tls.ConnectionState) error {
				// --- SECURITY CRITICAL ---
				// We MUST perform our own verification here.
				opts := x509.VerifyOptions{
					DNSName:       cs.ServerName,
					Intermediates: x509.NewCertPool(),
				}
				if len(cs.PeerCertificates) <= 1 {
					// Not enough certificates to build a chain with intermediates.
					// Can still check the single cert against system roots.
				} else {
					for _, cert := range cs.PeerCertificates[1:] {
						opts.Intermediates.AddCert(cert)
					}
				}

				if _, err := cs.PeerCertificates[0].Verify(opts); err != nil {
					// Allow connection to proceed for fingerprinting purposes
					// even with an invalid cert, but do not cache issuer info.
					return nil
				}

				// If verification is successful, cache the issuer's Common Name.
				issuer := cs.PeerCertificates[0].Issuer.CommonName
				wappalyze.certInfoCache.Store(cs.ServerName, issuer)
				return nil
			},
		},
	}

	wappalyze.httpClient = &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}

	err := wappalyze.loadFingerprints()
	if err != nil {
		return nil, err
	}
	return wappalyze, nil
}

// NewFromFile creates a new tech detection instance from a file
// this allows using the latest fingerprints without recompiling the code
// loadEmbedded indicates whether to load the embedded fingerprints
// supersede indicates whether to overwrite the embedded fingerprints (if loaded) with the file fingerprints if the app name conflicts
// supersede is only used if loadEmbedded is true
func NewFromFile(filePath string, loadEmbedded, supersede bool) (*Wappalyze, error) {
	wappalyze := &Wappalyze{
		fingerprints: &CompiledFingerprints{
			Apps:             make(map[string]*CompiledFingerprint),
			domPatternsByTag: make(map[string]map[string][]string),
		},
	}

	err := wappalyze.loadFingerprintsFromFile(filePath, loadEmbedded, supersede)
	if err != nil {
		return nil, err
	}

	return wappalyze, nil
}

// GetFingerprints returns the original fingerprints
func (s *Wappalyze) GetFingerprints() *Fingerprints {
	return s.original
}

// GetCompiledFingerprints returns the compiled fingerprints
func (s *Wappalyze) GetCompiledFingerprints() *CompiledFingerprints {
	return s.fingerprints
}

// analyze is the core detection function that performs all available detection methods
// and returns a richResult containing all possible outputs.
// This is the central implementation that all public methods should delegate to.
// This implementation uses a fully parallel concurrency model for all I/O operations.
func (s *Wappalyze) analyze(resp *http.Response, body []byte) richResult {
	// Call the new fully pipelined implementation
	return s.analyzeWithPipeline(resp, body)
}

// loadFingerprints loads the fingerprints and compiles them
func (s *Wappalyze) loadFingerprints() error {
	var fingerprintsStruct Fingerprints
	err := json.Unmarshal([]byte(fingerprints), &fingerprintsStruct)
	if err != nil {
		return err
	}

	s.original = &fingerprintsStruct
	for appName, fingerprint := range fingerprintsStruct.Apps {
		s.fingerprints.Apps[appName] = compileFingerprint(fingerprint)

		// Register DOM patterns for optimization
		for domSelector := range fingerprint.Dom {
			s.fingerprints.registerDOMPattern(appName, domSelector)
		}
	}
	return nil
}

// loadFingerprints loads the fingerprints from the provided file and compiles them
func (s *Wappalyze) loadFingerprintsFromFile(filePath string, loadEmbedded, supersede bool) error {

	f, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	var fingerprintsStruct Fingerprints
	err = json.Unmarshal(f, &fingerprintsStruct)
	if err != nil {
		return err
	}

	if len(fingerprintsStruct.Apps) == 0 {
		return fmt.Errorf("no fingerprints found in file: %s", filePath)
	}

	if loadEmbedded {
		var embedded Fingerprints
		err := json.Unmarshal([]byte(fingerprints), &embedded)
		if err != nil {
			return err
		}

		s.original = &embedded

		for app, fingerprint := range fingerprintsStruct.Apps {
			if _, ok := s.original.Apps[app]; ok && supersede {
				s.original.Apps[app] = fingerprint
			} else {
				s.original.Apps[app] = fingerprint
			}
		}

	} else {
		s.original = &fingerprintsStruct
	}

	for appName, fingerprint := range s.original.Apps {
		s.fingerprints.Apps[appName] = compileFingerprint(fingerprint)

		// Register DOM patterns for optimization
		for domSelector := range fingerprint.Dom {
			s.fingerprints.registerDOMPattern(appName, domSelector)
		}
	}

	return nil
}

// Fingerprint identifies technologies on a target,
// based on the received response headers and body.
//
// Body should not be mutated while this function is being called, or it may
// lead to unexpected things.
func (s *Wappalyze) Fingerprint(headers map[string][]string, body []byte) map[string]struct{} {
	// For backward compatibility, create a minimal response with just the headers
	resp := &http.Response{
		Header: headers,
	}

	// Use the core analysis function
	result := s.analyze(resp, body)

	// Return just the detected technologies
	return result.technologies
}

// FingerprintWithResponse identifies technologies using the full http.Response,
// which allows for DNS lookups based on the domain in the URL.
func (s *Wappalyze) FingerprintWithResponse(resp *http.Response, body []byte) map[string]struct{} {
	// Use the core analysis function directly with the response
	result := s.analyze(resp, body)

	// Return just the detected technologies
	return result.technologies
}

// FingerprintWithURL identifies technologies on a target with a URL,
// which allows for DNS lookups based on the domain in the URL.
func (s *Wappalyze) FingerprintWithURL(headers map[string][]string, body []byte, targetURL string) map[string]struct{} {
	// Create a minimal response object with the headers and URL
	resp := &http.Response{
		Header: headers,
	}

	// Add the URL if provided
	if targetURL != "" {
		parsedURL, err := url.Parse(targetURL)
		if err == nil {
			resp.Request = &http.Request{
				URL: parsedURL,
			}
		}
	}

	// Use the core analysis function
	result := s.analyze(resp, body)

	// Return just the detected technologies
	return result.technologies
}

type UniqueFingerprints struct {
	values map[string]uniqueFingerprintMetadata
}

type uniqueFingerprintMetadata struct {
	confidence int
	version    string
}

func NewUniqueFingerprints() UniqueFingerprints {
	return UniqueFingerprints{
		values: make(map[string]uniqueFingerprintMetadata),
	}
}

func (u UniqueFingerprints) GetValues() map[string]struct{} {
	values := make(map[string]struct{}, len(u.values))
	for k, v := range u.values {
		if v.confidence == 0 {
			continue
		}
		values[FormatAppVersion(k, v.version)] = struct{}{}
	}
	return values
}

const versionSeparator = ":"

func (u UniqueFingerprints) SetIfNotExists(value, version string, confidence int) {
	if _, ok := u.values[value]; ok {
		new := u.values[value]
		updatedConfidence := new.confidence + confidence
		if updatedConfidence > 100 {
			updatedConfidence = 100
		}
		new.confidence = updatedConfidence
		if new.version == "" && version != "" {
			new.version = version
		}
		u.values[value] = new
		return
	}

	u.values[value] = uniqueFingerprintMetadata{
		confidence: confidence,
		version:    version,
	}
}

type matchPartResult struct {
	application string
	confidence  int
	version     string
}

// FingerprintWithTitle identifies technologies on a target,
// based on the received response headers and body.
// It also returns the title of the page.
//
// Body should not be mutated while this function is being called, or it may
// lead to unexpected things.
func (s *Wappalyze) FingerprintWithTitle(headers map[string][]string, body []byte) (map[string]struct{}, string) {
	// Create a minimal response object with the headers
	resp := &http.Response{
		Header: headers,
	}

	// Use the core analysis function
	result := s.analyze(resp, body)

	// Return technologies and title
	return result.technologies, result.title
}

// FingerprintWithTitleAndURL identifies technologies on a target with a URL,
// which allows for DNS lookups based on the domain in the URL.
// It also returns the title of the page.
func (s *Wappalyze) FingerprintWithTitleAndURL(headers map[string][]string, body []byte, targetURL string) (map[string]struct{}, string) {
	// Create a minimal response object with the headers and URL
	resp := &http.Response{
		Header: headers,
	}

	// Add the URL if provided
	if targetURL != "" {
		parsedURL, err := url.Parse(targetURL)
		if err == nil {
			resp.Request = &http.Request{
				URL: parsedURL,
			}
		}
	}

	// Use the core analysis function
	result := s.analyze(resp, body)

	// Return technologies and title
	return result.technologies, result.title
}

// FingerprintWithInfo identifies technologies on a target,
// based on the received response headers and body.
// It also returns basic information about the technology, such as description
// and website URL as well as icon.
//
// Body should not be mutated while this function is being called, or it may
// lead to unexpected things.
func (s *Wappalyze) FingerprintWithInfo(headers map[string][]string, body []byte) map[string]AppInfo {
	// Create a minimal response object with the headers
	resp := &http.Response{
		Header: headers,
	}

	// Use the core analysis function
	result := s.analyze(resp, body)

	// Return application info
	return result.appInfo
}

// FingerprintWithInfoAndURL identifies technologies on a target with a URL,
// which allows for DNS lookups based on the domain in the URL.
// It also returns basic information about the technology.
func (s *Wappalyze) FingerprintWithInfoAndURL(headers map[string][]string, body []byte, targetURL string) map[string]AppInfo {
	// Create a minimal response object with the headers and URL
	resp := &http.Response{
		Header: headers,
	}

	// Add the URL if provided
	if targetURL != "" {
		parsedURL, err := url.Parse(targetURL)
		if err == nil {
			resp.Request = &http.Request{
				URL: parsedURL,
			}
		}
	}

	// Use the core analysis function
	result := s.analyze(resp, body)

	// Return application info
	return result.appInfo
}

func AppInfoFromFingerprint(fingerprint *CompiledFingerprint) AppInfo {
	categories := make([]string, 0, len(fingerprint.cats))
	for _, cat := range fingerprint.cats {
		if category, ok := categoriesMapping[cat]; ok {
			categories = append(categories, category.Name)
		}
	}
	return AppInfo{
		Description: fingerprint.description,
		Website:     fingerprint.website,
		Icon:        fingerprint.icon,
		CPE:         fingerprint.cpe,
		Categories:  categories,
	}
}

// fetchAndAnalyzeRobotsTxt fetches robots.txt from the specified URL and analyzes it for technology fingerprints

func (s *Wappalyze) fetchAndAnalyzeRobotsTxt(robotsURL string, ctx context.Context) []matchPartResult {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", robotsURL, nil)
	if err != nil {
		return nil
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5931.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Only process if status code is 200
	if resp.StatusCode != 200 {
		return nil
	}

	// Read robots.txt content
	robotsContent, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
	if err != nil {
		return nil
	}

	// Match robots.txt patterns against content with timeout
	return s.fingerprints.matchString(string(robotsContent), robotsPart, s.regexTimeout)
}

// FingerprintWithCats identifies technologies on a target,
// based on the received response headers and body.
// It also returns categories information about the technology, is there's any
// Body should not be mutated while this function is being called, or it may
// lead to unexpected things.
func (s *Wappalyze) FingerprintWithCats(headers map[string][]string, body []byte) map[string]CatsInfo {
	// Create a minimal response object with the headers
	resp := &http.Response{
		Header: headers,
	}

	// Use the core analysis function
	result := s.analyze(resp, body)

	// Return category info
	return result.categoryInfo
}

// FingerprintWithCatsAndURL identifies technologies on a target with a URL,
// which allows for DNS lookups based on the domain in the URL.
// It also returns categories information about the technology.
func (s *Wappalyze) FingerprintWithCatsAndURL(headers map[string][]string, body []byte, targetURL string) map[string]CatsInfo {
	// Create a minimal response object with the headers and URL
	resp := &http.Response{
		Header: headers,
	}

	// Add the URL if provided
	if targetURL != "" {
		parsedURL, err := url.Parse(targetURL)
		if err == nil {
			resp.Request = &http.Request{
				URL: parsedURL,
			}
		}
	}

	// Use the core analysis function
	result := s.analyze(resp, body)

	// Return category info
	return result.categoryInfo
}
