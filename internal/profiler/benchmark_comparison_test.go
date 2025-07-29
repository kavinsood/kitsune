package profiler

import (
	"bytes"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	
	"golang.org/x/net/html"
)

// Implementation of the original (unoptimized) checkBody function for benchmarking
func checkBodyUnoptimized(s *Wappalyze, body []byte) ([]matchPartResult, []string) {
	var technologies []matchPartResult
	var scriptURLs []string

	bodyString := unsafeToString(body)

	technologies = append(
		technologies,
		s.fingerprints.matchString(bodyString, htmlPart, s.regexTimeout)...,
	)

	// Tokenize the HTML document and check for fingerprints as required
	tokenizer := html.NewTokenizer(bytes.NewReader(body))

	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			return technologies, scriptURLs
		case html.StartTagToken:
			token := tokenizer.Token()
			
			// Process any DOM patterns that match this tag
			for app, fingerprint := range s.fingerprints.Apps {
				domPatternMatched := false
				
				for domSelector := range fingerprint.dom {
					// Parse the DOM selector (very simplified approach)
					// Format: element[attribute*='value']
					
					// Check if the selector matches this element
					elementMatches := false
					
					// Extract element name from selector
					elementName := domSelector
					attrStartIdx := strings.Index(domSelector, "[")
					if attrStartIdx > 0 {
						elementName = domSelector[:attrStartIdx]
					}
					
					// Check if element name matches (or is a wildcard)
					if elementName == "*" || elementName == token.Data {
						elementMatches = true
					}
					
					// If element name matches, check attributes if there are any
					if elementMatches && attrStartIdx > 0 && strings.Contains(domSelector, "=") {
						// Extract attribute from selector
						attrEndIdx := strings.Index(domSelector[attrStartIdx:], "]")
						if attrEndIdx < 0 {
							continue // Invalid selector
						}
						
						attrStr := domSelector[attrStartIdx+1 : attrStartIdx+attrEndIdx]
						
						// Check for attribute match types: = (exact), *= (contains), ^= (starts with), $= (ends with)
						var matchType string
						if strings.Contains(attrStr, "*=") {
							matchType = "*="
						} else if strings.Contains(attrStr, "^=") {
							matchType = "^="
						} else if strings.Contains(attrStr, "$=") {
							matchType = "$="
						} else if strings.Contains(attrStr, "=") {
							matchType = "="
						} else {
							// Just checking for attribute existence
							for _, attr := range token.Attr {
								if attr.Key == strings.TrimSpace(attrStr) {
									domPatternMatched = true
									break
								}
							}
							continue
						}
						
						parts := strings.Split(attrStr, matchType)
						if len(parts) != 2 {
							continue // Invalid selector
						}
						
						attrName := strings.TrimSpace(parts[0])
						
						// Extract expected value, removing quotes if present
						attrValue := strings.TrimSpace(parts[1])
						if (strings.HasPrefix(attrValue, "'") && strings.HasSuffix(attrValue, "'")) ||
						   (strings.HasPrefix(attrValue, "\"") && strings.HasSuffix(attrValue, "\"")) {
							attrValue = attrValue[1 : len(attrValue)-1]
						}
						
						// Check each attribute on the token for a match
						for _, attr := range token.Attr {
							if attr.Key == attrName {
								// Case-insensitive comparison for attribute values
								tokenValue := strings.ToLower(attr.Val)
								selectorValue := strings.ToLower(attrValue)
								
								switch matchType {
								case "=":  // Exact match
									domPatternMatched = (tokenValue == selectorValue)
								case "*=": // Contains
									domPatternMatched = strings.Contains(tokenValue, selectorValue)
								case "^=": // Starts with
									domPatternMatched = strings.HasPrefix(tokenValue, selectorValue)
								case "$=": // Ends with
									domPatternMatched = strings.HasSuffix(tokenValue, selectorValue)
								}
								
								if domPatternMatched {
									break
								}
							}
						}
					}
					
					// If we matched a DOM pattern, add the technology
					if domPatternMatched {
						break // No need to check other patterns for this app
					}
				}
				
				if domPatternMatched {
					// Add the application
					technologies = append(technologies, matchPartResult{
						application: app,
						version:     "",
						confidence:  100,
					})
					
					// Add implied technologies
					for _, implied := range fingerprint.implies {
						technologies = append(technologies, matchPartResult{
							application: implied,
							version:     "",
							confidence:  100,
						})
					}
				}
			}
			
			// Continue with the existing tag-specific processing
			switch token.Data {
			case "script":
				// Check if the script tag has a source file to check
				source, found := getScriptSource(token)
				if found {
					// Add the script URL to our list for external JS analysis
					scriptURLs = append(scriptURLs, source)
					
					// Check the script tags for script fingerprints
					technologies = append(
						technologies,
						s.fingerprints.matchString(source, scriptPart, s.regexTimeout)...,
					)
					continue
				}

				// Check the text attribute of the tag for javascript based technologies.
				// The next token should be the contents of the script tag
				if tokenType := tokenizer.Next(); tokenType != html.TextToken {
					continue
				}

				// data := tokenizer.Token().Data
				// technologies = append(
				// 	technologies,
				// 	s.fingerprints.matchString(data, jsPart)...,
				// )
			case "meta":
				// For meta tag, we are only interested in name and content attributes.
				name, content, found := getMetaNameAndContent(token)
				if !found {
					continue
				}
				technologies = append(
					technologies,
					s.fingerprints.matchKeyValueString(name, content, metaPart, s.regexTimeout)...,
				)
			}
		case html.SelfClosingTagToken:
			token := tokenizer.Token()
			if token.Data != "meta" {
				continue
			}

			// Parse the meta tag and check for tech
			name, content, found := getMetaNameAndContent(token)
			if !found {
				continue
			}
			technologies = append(
				technologies,
				s.fingerprints.matchKeyValueString(name, content, metaPart, s.regexTimeout)...,
			)
		}
	}
}

func BenchmarkFingerprintUnoptimized(b *testing.B) {
	html, err := os.ReadFile("testdata/drupal.html")
	if err != nil {
		b.Skipf("Skipping benchmark: %v", err)
		return
	}

	headers := http.Header{
		"Server":        []string{"nginx/1.19.0"},
		"Content-Type":  []string{"text/html"},
		"X-Powered-By":  []string{"PHP/7.4.3"},
		"X-Drupal-Cache": []string{"HIT"},
	}

	wappalyzer, err := New()
	if err != nil {
		b.Fatal(err)
	}

	headersMap := make(map[string][]string)
	for k, v := range headers {
		headersMap[k] = v
	}

	// Replacement for Fingerprint with unoptimized checkBody
	fingerprint := func(headers map[string][]string, body []byte) map[string]struct{} {
		// For backward compatibility with existing tests, we'll use the original implementation
		// rather than forwarding to FingerprintWithURL
		uniqueFingerprints := NewUniqueFingerprints()

		// Lowercase everything that we have received to check
		normalizedBody := bytes.ToLower(body)
		normalizedHeaders := wappalyzer.normalizeHeaders(headers)

		// Run header based fingerprinting if the number
		// of header checks if more than 0.
		for _, app := range wappalyzer.checkHeaders(normalizedHeaders) {
			uniqueFingerprints.SetIfNotExists(app.application, app.version, app.confidence)
		}

		cookies := wappalyzer.findSetCookie(normalizedHeaders)
		// Run cookie based fingerprinting if we have a set-cookie header
		if len(cookies) > 0 {
			for _, app := range wappalyzer.checkCookies(cookies) {
				uniqueFingerprints.SetIfNotExists(app.application, app.version, app.confidence)
			}
		}

		// Check for stuff in the body finally
		bodyTech, _ := checkBodyUnoptimized(wappalyzer, normalizedBody)
		for _, app := range bodyTech {
			uniqueFingerprints.SetIfNotExists(app.application, app.version, app.confidence)
		}
		return uniqueFingerprints.GetValues()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fingerprint(headersMap, html)
	}
}

func BenchmarkFingerprintComparison(b *testing.B) {
	html, err := os.ReadFile("testdata/drupal.html")
	if err != nil {
		b.Skipf("Skipping benchmark: %v", err)
		return
	}

	headers := http.Header{
		"Server":        []string{"nginx/1.19.0"},
		"Content-Type":  []string{"text/html"},
		"X-Powered-By":  []string{"PHP/7.4.3"},
		"X-Drupal-Cache": []string{"HIT"},
	}

	wappalyzer, err := New()
	if err != nil {
		b.Fatal(err)
	}

	headersMap := make(map[string][]string)
	for k, v := range headers {
		headersMap[k] = v
	}

	// Create a response with a fake URL for the concurrent implementation
	resp := &http.Response{
		Header: headers,
		Request: &http.Request{
			URL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
			},
		},
	}

	// Benchmark original Fingerprint method
	b.Run("Fingerprint-Original", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			wappalyzer.Fingerprint(headersMap, html)
		}
	})

	// Benchmark FingerprintWithResponse (uses concurrent implementation)
	b.Run("FingerprintWithResponse-Concurrent", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			wappalyzer.FingerprintWithResponse(resp, html)
		}
	})

	// Benchmark FingerprintWithURL (uses concurrent implementation)
	b.Run("FingerprintWithURL-Concurrent", func(b *testing.B) {
		targetURL := "https://example.com"
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			wappalyzer.FingerprintWithURL(headersMap, html, targetURL)
		}
	})
}