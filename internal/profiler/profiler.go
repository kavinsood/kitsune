package profiler

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/kavinsood/kitsune/assets"
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
	// original holds the fingerprints in their JSON form. For the embedded
	// fingerprints it is only decoded if GetFingerprints is called.
	original     *Fingerprints
	originalOnce sync.Once

	fingerprints  *CompiledFingerprints
	regexTimeout  time.Duration
	httpClient    *http.Client
	certInfoCache *sync.Map
}

// New creates a new tech detection instance
//
// It uses the fingerprints compiled into the binary (see gen.go), so it
// costs next to nothing: regexes and selectors are compiled on first use.
func New() (*Wappalyze, error) {
	wappalyze := &Wappalyze{
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

	wappalyze.fingerprints = embeddedFingerprints()
	return wappalyze, nil
}

// embeddedFingerprints returns the fingerprints compiled into the binary,
// decoding them on first use.
func embeddedFingerprints() *CompiledFingerprints {
	embeddedOnce.Do(func() {
		f, err := decodeFingerprints(generatedFingerprints, generatedFingerprintText)
		if err != nil {
			// The data is generated and checked by tests, so this can't
			// happen.
			panic(err)
		}
		if !unboundedRepeats {
			f = f.withBoundedRepeats()
		}
		embedded = f
	})
	return embedded
}

var (
	embeddedOnce sync.Once
	embedded     *CompiledFingerprints
)

// NewFromFile creates a new tech detection instance from a file
// this allows using the latest fingerprints without recompiling the code
// loadEmbedded indicates whether to load the embedded fingerprints
// supersede indicates whether to overwrite the embedded fingerprints (if loaded) with the file fingerprints if the app name conflicts
// supersede is only used if loadEmbedded is true
//
// Unlike New, NewFromFile compiles every regex up front.
func NewFromFile(filePath string, loadEmbedded, supersede bool) (*Wappalyze, error) {
	wappalyze := &Wappalyze{}

	err := wappalyze.loadFingerprintsFromFile(filePath, loadEmbedded, supersede)
	if err != nil {
		return nil, err
	}

	return wappalyze, nil
}

// GetFingerprints returns the original fingerprints
//
// For the embedded fingerprints they are decoded from JSON on the first
// call, which takes a while.
func (s *Wappalyze) GetFingerprints() *Fingerprints {
	s.originalOnce.Do(func() {
		if s.original == nil {
			s.original = embeddedOriginal()
		}
	})
	return s.original
}

// embeddedOriginal decodes the embedded fingerprints.
func embeddedOriginal() *Fingerprints {
	var embedded Fingerprints
	if err := json.Unmarshal([]byte(assets.FingerprintsJSON), &embedded); err != nil {
		// The embedded JSON is valid: kitsune-gen compiled it.
		panic(err)
	}
	return &embedded
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

	compiled, _ := compileFingerprints(fingerprintsStruct.Apps)

	if loadEmbedded {
		s.original = embeddedOriginal()

		// The file's fingerprints always replace the embedded ones of the
		// same name, whatever supersede says.
		for app, fingerprint := range fingerprintsStruct.Apps {
			s.original.Apps[app] = fingerprint
		}

		merged := &CompiledFingerprints{Apps: append([]*CompiledFingerprint(nil), compiled.Apps...)}
		for _, fp := range embeddedFingerprints().Apps {
			if _, ok := fingerprintsStruct.Apps[fp.name]; !ok {
				merged.Apps = append(merged.Apps, fp)
			}
		}
		merged.buildIndexes()
		compiled = merged
	} else {
		s.original = &fingerprintsStruct
	}
	s.fingerprints = compiled

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
	description, website, icon, cpe := fingerprint.appInfo()
	return AppInfo{
		Description: description,
		Website:     website,
		Icon:        icon,
		CPE:         cpe,
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
	robotsContent, err := readString(resp, 1024*1024) // 1MB limit
	if err != nil {
		return nil
	}

	// Match robots.txt patterns against content with timeout
	return s.fingerprints.matchString(robotsContent, robotsPart, s.regexTimeout)
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
