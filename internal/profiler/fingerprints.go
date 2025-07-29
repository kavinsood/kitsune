package profiler

import (
	"fmt"
	"strings"
	"time"
)

// Fingerprints contains a map of fingerprints for tech detection
type Fingerprints struct {
	// Apps is organized as <name, fingerprint>
	Apps map[string]*Fingerprint `json:"apps"`
}

// Fingerprint is a single piece of information about a tech validated and normalized
type Fingerprint struct {
	Cats        []int                             `json:"cats"`
	CSS         []string                          `json:"css"`
	Cookies     map[string]string                 `json:"cookies"`
	Dom         map[string]map[string]interface{} `json:"dom"`
	JS          map[string]string                 `json:"js"`
	Headers     map[string]string                 `json:"headers"`
	HTML        []string                          `json:"html"`
	Script      []string                          `json:"scripts"`
	ScriptSrc   []string                          `json:"scriptSrc"`
	Meta        map[string][]string               `json:"meta"`
	DNS         map[string][]string               `json:"dns"`
	Robots      []string                          `json:"robots"`
	CertIssuer  []string                          `json:"certIssuer"`
	Implies     []string                          `json:"implies"`
	Description string                            `json:"description"`
	Website     string                            `json:"website"`
	CPE         string                            `json:"cpe"`
	Icon        string                            `json:"icon"`
}

// CompiledFingerprints contains a map of fingerprints for tech detection
type CompiledFingerprints struct {
	// Apps is organized as <name, fingerprint>
	Apps map[string]*CompiledFingerprint
	
	// domPatternsByTag provides a quick lookup map for DOM patterns by HTML tag name
	// organized as <tag_name, map<app_name, selectors>>
	domPatternsByTag map[string]map[string][]string
}

// CompiledFingerprint contains the compiled fingerprints from the tech json
type CompiledFingerprint struct {
	// cats contain categories that are implicit with this tech
	cats []int
	// implies contains technologies that are implicit with this tech
	implies []string
	// description contains fingerprint description
	description string
	// website contains a URL associated with the fingerprint
	website string
	// icon contains a Icon associated with the fingerprint
	icon string
	// cookies contains fingerprints for target cookies
	cookies map[string]*ParsedPattern
	// js contains fingerprints for the js file
	js map[string]*ParsedPattern
	// dom contains fingerprints for the target dom
	dom map[string]map[string]*ParsedPattern
	// headers contains fingerprints for target headers
	headers map[string]*ParsedPattern
	// html contains fingerprints for the target HTML
	html []*ParsedPattern
	// script contains fingerprints for scripts
	script []*ParsedPattern
	// scriptSrc contains fingerprints for script srcs
	scriptSrc []*ParsedPattern
	// meta contains fingerprints for meta tags
	meta map[string][]*ParsedPattern
	// dns contains fingerprints for DNS records
	dns map[string][]*ParsedPattern
	// robots contains fingerprints for robots.txt content
	robots []*ParsedPattern
	// certIssuer contains fingerprints for TLS certificate issuers
	certIssuer []*ParsedPattern
	// css contains fingerprints for CSS content
	css []*ParsedPattern
	// cpe contains the cpe for a fingerpritn
	cpe string
}

func (f *CompiledFingerprint) GetJSRules() map[string]*ParsedPattern {
	return f.js
}

func (f *CompiledFingerprint) GetDOMRules() map[string]map[string]*ParsedPattern {
	return f.dom
}

// AppInfo contains basic information about an App.
type AppInfo struct {
	Description string
	Website     string
	CPE         string
	Icon        string
	Categories  []string
}

// CatsInfo contains basic information about an App.
type CatsInfo struct {
	Cats []int
}

// part is the part of the fingerprint to match
type part int

// parts that can be matched
const (
	cookiesPart part = iota + 1
	jsPart
	headersPart
	htmlPart
	scriptPart
	metaPart
	dnsPart
	robotsPart
	certIssuerPart
	cssPart
)

// loadPatterns loads the fingerprint patterns and compiles regexes
func compileFingerprint(fingerprint *Fingerprint) *CompiledFingerprint {
	compiled := &CompiledFingerprint{
		cats:        fingerprint.Cats,
		implies:     fingerprint.Implies,
		description: fingerprint.Description,
		website:     fingerprint.Website,
		icon:        fingerprint.Icon,
		dom:         make(map[string]map[string]*ParsedPattern),
		cookies:     make(map[string]*ParsedPattern),
		js:          make(map[string]*ParsedPattern),
		headers:     make(map[string]*ParsedPattern),
		html:        make([]*ParsedPattern, 0, len(fingerprint.HTML)),
		script:      make([]*ParsedPattern, 0, len(fingerprint.Script)),
		scriptSrc:   make([]*ParsedPattern, 0, len(fingerprint.ScriptSrc)),
		meta:        make(map[string][]*ParsedPattern),
		dns:         make(map[string][]*ParsedPattern),
		robots:      make([]*ParsedPattern, 0, len(fingerprint.Robots)),
		certIssuer:  make([]*ParsedPattern, 0, len(fingerprint.CertIssuer)),
		css:         make([]*ParsedPattern, 0, len(fingerprint.CSS)),
		cpe:         fingerprint.CPE,
	}

	for dom, patterns := range fingerprint.Dom {
		compiled.dom[dom] = make(map[string]*ParsedPattern)

		// Add this DOM selector to the element-indexed lookup map
		for attr, value := range patterns {
			switch attr {
			case "exists":
				// Just the existence is enough, no need for pattern matching
				compiled.dom[dom][attr] = nil
			case "text":
				// Text content matching pattern
				patternStr, ok := value.(string)
				if !ok {
					continue
				}
				pattern, err := ParsePattern(patternStr)
				if err != nil {
					continue
				}
				compiled.dom[dom][attr] = pattern
			case "attributes":
				// Process attribute patterns
				attrMap, ok := value.(map[string]interface{})
				if !ok {
					continue
				}
				for attrName, attrValue := range attrMap {
					patternStr, ok := attrValue.(string)
					if !ok {
						continue
					}
					pattern, err := ParsePattern(patternStr)
					if err != nil {
						continue
					}
					compiled.dom[dom][attrName] = pattern
				}
			default:
				// Handle direct attribute matching (like "href", "id", "class")
				patternStr, ok := value.(string)
				if !ok {
					continue
				}
				pattern, err := ParsePattern(patternStr)
				if err != nil {
					continue
				}
				compiled.dom[dom][attr] = pattern
			}
		}
	}

	for header, pattern := range fingerprint.Cookies {
		fingerprint, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.cookies[header] = fingerprint
	}

	for k, pattern := range fingerprint.JS {
		fingerprint, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.js[k] = fingerprint
	}

	for header, pattern := range fingerprint.Headers {
		fingerprint, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.headers[header] = fingerprint
	}

	for _, pattern := range fingerprint.HTML {
		fingerprint, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.html = append(compiled.html, fingerprint)
	}

	for _, pattern := range fingerprint.Script {
		fingerprint, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.script = append(compiled.script, fingerprint)
	}

	for _, pattern := range fingerprint.ScriptSrc {
		fingerprint, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.scriptSrc = append(compiled.scriptSrc, fingerprint)
	}

	for meta, patterns := range fingerprint.Meta {
		var compiledList []*ParsedPattern

		for _, pattern := range patterns {
			fingerprint, err := ParsePattern(pattern)
			if err != nil {
				continue
			}
			compiledList = append(compiledList, fingerprint)
		}
		compiled.meta[meta] = compiledList
	}

	// Process DNS record patterns
	for recordType, patterns := range fingerprint.DNS {
		var compiledList []*ParsedPattern

		for _, pattern := range patterns {
			fingerprint, err := ParsePattern(pattern)
			if err != nil {
				continue
			}
			compiledList = append(compiledList, fingerprint)
		}
		compiled.dns[recordType] = compiledList
	}
	
	// Process robots.txt patterns
	for _, pattern := range fingerprint.Robots {
		fingerprint, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.robots = append(compiled.robots, fingerprint)
	}
	
	// Process TLS certificate issuer patterns
	for _, pattern := range fingerprint.CertIssuer {
		fingerprint, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.certIssuer = append(compiled.certIssuer, fingerprint)
	}
	
	// Process CSS patterns
	for _, pattern := range fingerprint.CSS {
		fingerprint, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.css = append(compiled.css, fingerprint)
	}

	return compiled
}

// matchString matches a string for the fingerprints
func (f *CompiledFingerprints) matchString(data string, part part, timeout time.Duration) []matchPartResult {
	// Create a simplified struct just for timeout access
	s := struct {
		wappalyze struct {
			regexTimeout time.Duration
		}
	}{
		wappalyze: struct {
			regexTimeout time.Duration
		}{
			regexTimeout: timeout,
		},
	}
	var matched bool
	var technologies []matchPartResult

	for app, fingerprint := range f.Apps {
		var version string
		confidence := 100

		switch part {
		case jsPart:
			for _, pattern := range fingerprint.js {
				if valid, versionString := pattern.Evaluate(data, s.wappalyze.regexTimeout); valid {
					matched = true
					if version == "" && versionString != "" {
						version = versionString
					}
					confidence = pattern.Confidence
				}
			}
		case scriptPart:
			for _, pattern := range fingerprint.scriptSrc {
				if valid, versionString := pattern.Evaluate(data, s.wappalyze.regexTimeout); valid {
					matched = true
					if version == "" && versionString != "" {
						version = versionString
					}
					confidence = pattern.Confidence
				}
			}
		case htmlPart:
			for _, pattern := range fingerprint.html {
				if valid, versionString := pattern.Evaluate(data, s.wappalyze.regexTimeout); valid {
					matched = true
					if version == "" && versionString != "" {
						version = versionString
					}
					confidence = pattern.Confidence
				}
			}
		case robotsPart:
			for _, pattern := range fingerprint.robots {
				if valid, versionString := pattern.Evaluate(data, s.wappalyze.regexTimeout); valid {
					matched = true
					if version == "" && versionString != "" {
						version = versionString
					}
					confidence = pattern.Confidence
				}
			}
		case certIssuerPart:
			for _, pattern := range fingerprint.certIssuer {
				if valid, versionString := pattern.Evaluate(data, s.wappalyze.regexTimeout); valid {
					matched = true
					if version == "" && versionString != "" {
						version = versionString
					}
					confidence = pattern.Confidence
				}
			}
		case cssPart:
			// Use dedicated CSS patterns
			for _, pattern := range fingerprint.css {
				if valid, versionString := pattern.Evaluate(data, s.wappalyze.regexTimeout); valid {
					matched = true
					if version == "" && versionString != "" {
						version = versionString
					}
					confidence = pattern.Confidence
				}
			}
		}

		// If no match, continue with the next fingerprint
		if !matched {
			continue
		}

		// Append the technologies as well as implied ones
		technologies = append(technologies, matchPartResult{
			application: app,
			version:     version,
			confidence:  confidence,
		})
		if len(fingerprint.implies) > 0 {
			for _, implies := range fingerprint.implies {
				technologies = append(technologies, matchPartResult{
					application: implies,
					confidence:  confidence,
				})
			}
		}
		matched = false
	}
	return technologies
}

// matchKeyValue matches a key-value store map for the fingerprints
func (f *CompiledFingerprints) matchKeyValueString(key, value string, part part, timeout time.Duration) []matchPartResult {
	var matched bool
	var technologies []matchPartResult

	for app, fingerprint := range f.Apps {
		var version string
		confidence := 100

		switch part {
		case cookiesPart:
			for data, pattern := range fingerprint.cookies {
				if data != key {
					continue
				}

				if valid, versionString := pattern.Evaluate(value, timeout); valid {
					matched = true
					if version == "" && versionString != "" {
						version = versionString
					}
					confidence = pattern.Confidence
					break
				}
			}
		case headersPart:
			for data, pattern := range fingerprint.headers {
				if data != key {
					continue
				}

				if valid, versionString := pattern.Evaluate(value, timeout); valid {
					matched = true
					if version == "" && versionString != "" {
						version = versionString
					}
					confidence = pattern.Confidence
					break
				}
			}
		case metaPart:
			for data, patterns := range fingerprint.meta {
				if data != key {
					continue
				}

				for _, pattern := range patterns {
					if valid, versionString := pattern.Evaluate(value, timeout); valid {
						matched = true
						if version == "" && versionString != "" {
							version = versionString
						}
						confidence = pattern.Confidence
						break
					}
				}
			}
		}

		// If no match, continue with the next fingerprint
		if !matched {
			continue
		}

		technologies = append(technologies, matchPartResult{
			application: app,
			version:     version,
			confidence:  confidence,
		})
		if len(fingerprint.implies) > 0 {
			for _, implies := range fingerprint.implies {
				technologies = append(technologies, matchPartResult{
					application: implies,
					confidence:  confidence,
				})
			}
		}
		matched = false
	}
	return technologies
}

// matchDNSRecords matches DNS records against fingerprint patterns
func (f *CompiledFingerprints) matchDNSRecords(dnsRecords map[string][]string, timeout time.Duration) []matchPartResult {
	var matched bool
	var technologies []matchPartResult

	for app, fingerprint := range f.Apps {
		var version string
		confidence := 100

		// Skip if fingerprint has no DNS patterns
		if len(fingerprint.dns) == 0 {
			continue
		}

		for recordType, patterns := range fingerprint.dns {
			recordValues, ok := dnsRecords[recordType]
			if !ok {
				continue // No matching record type found
			}

			// Try to match any record value against any pattern for this record type
			for _, recordValue := range recordValues {
				for _, pattern := range patterns {
					if valid, versionString := pattern.Evaluate(recordValue, timeout); valid {
						matched = true
						if version == "" && versionString != "" {
							version = versionString
						}
						confidence = pattern.Confidence
						break
					}
				}
				// If we found a match in this record type, no need to check more values
				if matched {
					break
				}
			}
		}

		// If no match, continue with the next fingerprint
		if !matched {
			continue
		}

		// Append the technologies as well as implied ones
		technologies = append(technologies, matchPartResult{
			application: app,
			version:     version,
			confidence:  confidence,
		})
		if len(fingerprint.implies) > 0 {
			for _, implies := range fingerprint.implies {
				technologies = append(technologies, matchPartResult{
					application: implies,
					confidence:  confidence,
				})
			}
		}
		matched = false
	}
	return technologies
}

// matchMapString matches a key-value store map for the fingerprints
func (f *CompiledFingerprints) matchMapString(keyValue map[string]string, part part, timeout time.Duration) []matchPartResult {
	var matched bool
	var technologies []matchPartResult

	for app, fingerprint := range f.Apps {
		var version string
		confidence := 100

		switch part {
		case cookiesPart:
			for data, pattern := range fingerprint.cookies {
				value, ok := keyValue[data]
				if !ok {
					continue
				}
				if pattern == nil {
					matched = true
				}
				if valid, versionString := pattern.Evaluate(value, timeout); valid {
					matched = true
					if version == "" && versionString != "" {
						version = versionString
					}
					confidence = pattern.Confidence
					break
				}
			}
		case headersPart:
			for data, pattern := range fingerprint.headers {
				value, ok := keyValue[data]
				if !ok {
					continue
				}

				if valid, versionString := pattern.Evaluate(value, timeout); valid {
					matched = true
					if version == "" && versionString != "" {
						version = versionString
					}
					confidence = pattern.Confidence
					break
				}
			}
		case metaPart:
			for data, patterns := range fingerprint.meta {
				value, ok := keyValue[data]
				if !ok {
					continue
				}

				for _, pattern := range patterns {
					if valid, versionString := pattern.Evaluate(value, timeout); valid {
						matched = true
						if version == "" && versionString != "" {
							version = versionString
						}
						confidence = pattern.Confidence
						break
					}
				}
			}
		}

		// If no match, continue with the next fingerprint
		if !matched {
			continue
		}

		technologies = append(technologies, matchPartResult{
			application: app,
			version:     version,
			confidence:  confidence,
		})
		if len(fingerprint.implies) > 0 {
			for _, implies := range fingerprint.implies {
				technologies = append(technologies, matchPartResult{
					application: implies,
					confidence:  confidence,
				})
			}
		}
		matched = false
	}
	return technologies
}

func FormatAppVersion(app, version string) string {
	if version == "" {
		return app
	}
	return fmt.Sprintf("%s:%s", app, version)
}

// GetFingerprints returns the fingerprint string from wappalyzer
func GetFingerprints() string {
	return fingerprints
}

// registerDOMPattern registers a DOM pattern in the tag-based lookup map
func (f *CompiledFingerprints) registerDOMPattern(app string, domSelector string) {
	// Extract element name from selector for optimization
	elementName := domSelector
	attrStartIdx := strings.Index(domSelector, "[")
	if attrStartIdx > 0 {
		elementName = domSelector[:attrStartIdx]
	} else if elementName == "*" {
		// Special case: wildcard selector needs to be registered for all tags
		// Just store it as "*" and the matching logic will handle it
	}

	// Initialize map for this tag if needed
	if _, exists := f.domPatternsByTag[elementName]; !exists {
		f.domPatternsByTag[elementName] = make(map[string][]string)
	}

	// Initialize slice for this app if needed
	if _, exists := f.domPatternsByTag[elementName][app]; !exists {
		f.domPatternsByTag[elementName][app] = make([]string, 0)
	}

	// Add the selector to the lookup map
	f.domPatternsByTag[elementName][app] = append(
		f.domPatternsByTag[elementName][app], 
		domSelector,
	)
}

// preprocessDOMPatterns organizes DOM patterns by HTML tag name for efficient lookup
func (s *Wappalyze) preprocessDOMPatterns() {
	// Initialize or clear the lookup map
	s.fingerprints.domPatternsByTag = make(map[string]map[string][]string)

	// Process each app's DOM patterns
	for appName, fingerprint := range s.fingerprints.Apps {
		// Skip if app has no DOM patterns
		if len(fingerprint.dom) == 0 {
			continue
		}

		// Register each DOM selector for this app
		for domSelector := range fingerprint.dom {
			s.fingerprints.registerDOMPattern(appName, domSelector)
		}
	}
}
