package profiler

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// AnalyzeWithPipeline is an exported version of analyzeWithPipeline for benchmarking
// It returns the full richResult containing all detection information
func (s *Wappalyze) AnalyzeWithPipeline(resp *http.Response, body []byte) richResult {
	return s.analyzeWithPipeline(resp, body)
}

// analyzeWithPipeline matches everything known about a page: its URL,
// headers, cookies, TLS certificate, HTML, and the DNS records of its host
// and the scripts and stylesheets it links to, which are fetched
// concurrently as soon as they are found.
func (s *Wappalyze) analyzeWithPipeline(resp *http.Response, body []byte) richResult {
	var pageURL *url.URL
	if resp != nil && resp.Request != nil && resp.Request.URL != nil {
		pageURL = resp.Request.URL
	}

	var mu sync.Mutex
	var matches []matchPartResult
	add := func(found []matchPartResult) {
		mu.Lock()
		matches = append(matches, found...)
		mu.Unlock()
	}

	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	jsContent := make(map[string]string)
	cssContent := make(map[string]string)
	var baseURL string
	if pageURL != nil {
		baseURL = pageURL.String()
	}
	assetFetcher := NewAssetFetcher(baseURL, ctx, &wg, 10, &jsContent, &cssContent)
	assetFetcher.Start()

	if pageURL != nil && pageURL.Hostname() != "" {
		host := pageURL.Hostname()
		wg.Add(1)
		go func() {
			defer wg.Done()
			dnsCtx, dnsCancel := context.WithTimeout(ctx, 5*time.Second)
			defer dnsCancel()
			if records := checkDNSWithContext(dnsCtx, host); len(records) > 0 {
				add(s.fingerprints.matchKeyValues(records, dnsPart, s.regexTimeout))
			}
		}()
		add(s.fingerprints.matchString(baseURL, urlPart, s.regexTimeout))
	}

	if resp != nil {
		headers := normalizeHeaders(resp.Header)
		add(s.fingerprints.matchKeyValues(headers, headersPart, s.regexTimeout))
		add(s.fingerprints.matchKeyValues(cookieValues(headers), cookiesPart, s.regexTimeout))
		if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
			add(s.fingerprints.matchString(certIssuer(resp.TLS.PeerCertificates[0]), certIssuerPart, s.regexTimeout))
		}
	}

	var title string
	if len(body) > 0 {
		// GTM container ids are found in the raw body, so the containers'
		// fetches start before the page is parsed.
		for _, id := range gtmContainerIDs(body, maxGTMContainers) {
			assetFetcher.AddGTMContainer(id)
		}
		var found []matchPartResult
		found, title = s.analyzeHTML(body, pageURL, assetFetcher)
		add(found)
	}

	// No more URLs will be sent to the fetcher.
	assetFetcher.Stop()
	wg.Wait()

	// Fetched scripts are matched like inline ones, but only their window
	// assignments create globals.
	for _, content := range jsContent {
		matches = append(matches, s.fingerprints.matchString(content, scriptPart, s.regexTimeout)...)
		matches = append(matches, s.fingerprints.matchJSGlobals(content, false)...)
	}
	for _, content := range cssContent {
		matches = append(matches, s.fingerprints.matchString(content, cssPart, s.regexTimeout)...)
	}
	for _, ev := range assetFetcher.GTMEvidence() {
		matches = append(matches, s.matchGTM(ev, pageURL)...)
	}

	return s.newRichResult(s.fingerprints.resolve(matches), title)
}

// certIssuer returns the issuer of cert as matched by certIssuer patterns:
// its organization (like "Let's Encrypt") and common name.
func certIssuer(cert *x509.Certificate) string {
	return strings.Join(append(cert.Issuer.Organization, cert.Issuer.CommonName), " ")
}

// newRichResult returns the result for the resolved detections.
func (s *Wappalyze) newRichResult(detections map[string]detection, title string) richResult {
	result := richResult{
		technologies: make(map[string]struct{}),
		title:        title,
		appInfo:      make(map[string]AppInfo),
		categoryInfo: make(map[string]CatsInfo),
		detections:   detections,
	}
	for app, d := range detections {
		if !d.reported() {
			continue
		}
		name := FormatAppVersion(app, d.version)
		result.technologies[name] = struct{}{}
		// resolve only returns techs that have a fingerprint.
		if fp := s.fingerprints.lookup(app); fp != nil {
			result.appInfo[name] = AppInfoFromFingerprint(fp)
			result.categoryInfo[name] = CatsInfo{Cats: fp.cats}
		}
	}
	return result
}
