package profiler

import (
	"bytes"
	"strings"
	
	"github.com/PuerkitoBio/goquery"
)

// analyzeDOM checks for DOM patterns in the HTML using goquery selectors
// and returns detected technologies
func (s *Wappalyze) analyzeDOM(doc *goquery.Document) []matchPartResult {
	var technologies []matchPartResult

	// Skip DOM detection in testing mode if needed
	if doc.Find("html").Length() == 0 {
		// This is likely a test with minimal/empty HTML
		return technologies
	}

	for appName, fingerprint := range s.fingerprints.Apps {
		// Skip if no DOM patterns for this app
		if len(fingerprint.dom) == 0 {
			continue
		}

		for selector, checks := range fingerprint.dom {
			// Use goquery to find all elements matching the selector
			elements := doc.Find(selector)
			
			// If no elements found, continue to next selector
			if elements.Length() == 0 {
				continue
			}
			
			// Check if any element matches all the pattern checks
			elements.EachWithBreak(func(i int, selection *goquery.Selection) bool {
				// Once an element is found, perform all checks defined for it
				allChecksPassed := true

				for checkType, pattern := range checks {
					checkPassed := false
					
					switch checkType {
					case "exists", "main":
						// The selector found an element, so this check passes by default
						checkPassed = true
					case "text":
						// Element text content check
						if pattern != nil {
							if matched, _ := pattern.Evaluate(selection.Text(), s.regexTimeout); matched {
								checkPassed = true
							}
						}
					default:
						// Attribute checks (like href, src, class, etc.)
						if pattern != nil {
							if attrVal, exists := selection.Attr(checkType); exists {
								if matched, _ := pattern.Evaluate(attrVal, s.regexTimeout); matched {
									checkPassed = true
								}
							}
						}
					}

					if !checkPassed {
						allChecksPassed = false
						return true // Continue to next element
					}
				}

				if allChecksPassed {
					// All checks for this selector passed
					technologies = append(technologies, matchPartResult{
						application: appName,
						confidence:  100,
					})
					
					// Add implied technologies
					for _, implied := range fingerprint.implies {
						technologies = append(technologies, matchPartResult{
							application: implied,
							confidence:  100,
						})
					}
					
					return false // Break the .EachWithBreak loop
				}
				return true // Continue to the next element matching the selector
			})
		}
	}
	
	return technologies
}

// parseBodyForDOMAnalysis parses HTML body into a goquery document
// and collects script and style URLs for further analysis
// It also handles HTML pattern matching on the raw HTML content
func (s *Wappalyze) parseBodyForDOMAnalysis(body []byte) (*goquery.Document, []string, []string) {
	var scriptURLs []string
	var styleURLs []string

	// Create goquery document from HTML body
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		// Return nil document if parsing fails
		return nil, scriptURLs, styleURLs
	}

	// Extract script URLs for JavaScript analysis
	doc.Find("script[src]").Each(func(i int, s *goquery.Selection) {
		if src, exists := s.Attr("src"); exists && src != "" {
			scriptURLs = append(scriptURLs, src)
		}
	})

	// Extract stylesheet URLs for CSS analysis
	doc.Find("link[rel=stylesheet][href]").Each(func(i int, s *goquery.Selection) {
		if href, exists := s.Attr("href"); exists && href != "" {
			styleURLs = append(styleURLs, href)
		}
	})

	return doc, scriptURLs, styleURLs
}

// analyzeMeta extracts and analyzes meta tags from the document
func (s *Wappalyze) analyzeMeta(doc *goquery.Document) []matchPartResult {
	var technologies []matchPartResult
	metaTags := make(map[string]string)

	// Process meta tags
	doc.Find("meta").Each(func(i int, elem *goquery.Selection) {
		// Look for name attribute first
		name, nameExists := elem.Attr("name")
		if !nameExists {
			// If name doesn't exist, try http-equiv
			name, nameExists = elem.Attr("http-equiv")
			if !nameExists {
				// No identifying attribute found
				return
			}
		}

		// Get content attribute
		content, contentExists := elem.Attr("content")
		if !contentExists || content == "" {
			return
		}

		// Store meta tag for processing
		metaTags[strings.ToLower(name)] = content
	})

	// Match all meta tags against fingerprints
	metaTech := s.fingerprints.matchMapString(metaTags, metaPart, s.regexTimeout)
	if len(metaTech) > 0 {
		technologies = append(technologies, metaTech...)
	}

	return technologies
}

// analyzeScriptSrc analyzes script src attributes for fingerprints
func (s *Wappalyze) analyzeScriptSrc(doc *goquery.Document) []matchPartResult {
	var technologies []matchPartResult

	// Process script tags with src attribute
	doc.Find("script[src]").Each(func(i int, elem *goquery.Selection) {
		src, exists := elem.Attr("src")
		if !exists || src == "" {
			return
		}

		// Match script src against fingerprints
		scriptTech := s.fingerprints.matchString(src, scriptPart, s.regexTimeout)
		if len(scriptTech) > 0 {
			technologies = append(technologies, scriptTech...)
		}
	})

	return technologies
}

