package profiler

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kavinsood/kitsune/assets"
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

// CompiledFingerprints contains the fingerprints for tech detection in the
// form used for matching.
//
// The embedded fingerprints are compiled at build time into a package-level
// CompiledFingerprints (see gen.go), which the linker lays out as static
// data, so it costs nothing at startup. Everything else is derived lazily.
type CompiledFingerprints struct {
	// Apps holds the fingerprints, sorted by name.
	Apps []*CompiledFingerprint

	// lists holds the literal lists the lookup structures below are built
	// from. Built on first use.
	listsOnce sync.Once
	lists     literalLists

	// literalMatchers finds the prefilter literals of every pattern of a
	// part in one pass over large inputs. Built on first use.
	literalMatchersOnce sync.Once
	literalMatchers     map[part]*literalMatcher

	// jsGlobals is the set of jsGlobalNames. Built on first use.
	jsGlobalsOnce sync.Once
	jsGlobals     map[string]struct{}

	// domLiterals finds the literals of the dom selectors. Built on first
	// use.
	domLiteralsOnce sync.Once
	domLiterals     *literalMatcher
}

// CompiledFingerprint contains the compiled fingerprints from the tech json
type CompiledFingerprint struct {
	// name is the name of the tech
	name string
	// cats contain categories that are implicit with this tech
	cats []int
	// implies contains technologies that are implicit with this tech
	implies []string
	// info holds the description, website, icon and cpe of the tech,
	// separated by NULs (see newInfo). One string instead of four keeps
	// the generated data small.
	info string
	// cookies contains fingerprints for target cookies, sorted by key
	cookies []keyedPattern
	// js contains fingerprints for the js file, sorted by key
	js []keyedPattern
	// dom contains fingerprints for the target dom, sorted by selector
	dom []domRule
	// headers contains fingerprints for target headers, sorted by key
	headers []keyedPattern
	// html contains fingerprints for the target HTML
	html []*ParsedPattern
	// script contains fingerprints for scripts
	script []*ParsedPattern
	// scriptSrc contains fingerprints for script srcs
	scriptSrc []*ParsedPattern
	// meta contains fingerprints for meta tags, sorted by key
	meta []keyedPatterns
	// dns contains fingerprints for DNS records, sorted by record type
	dns []keyedPatterns
	// robots contains fingerprints for robots.txt content
	robots []*ParsedPattern
	// certIssuer contains fingerprints for TLS certificate issuers
	certIssuer []*ParsedPattern
	// css contains fingerprints for CSS content
	css []*ParsedPattern
}

// newInfo returns the info field for the given description, website, icon
// and cpe, which must not contain NULs.
func newInfo(description, website, icon, cpe string) string {
	if description == "" && website == "" && icon == "" && cpe == "" {
		return ""
	}
	return description + "\x00" + website + "\x00" + icon + "\x00" + cpe
}

// appInfo returns the description, website, icon and cpe of the tech.
func (f *CompiledFingerprint) appInfo() (description, website, icon, cpe string) {
	if f.info == "" {
		return "", "", "", ""
	}
	fields := strings.SplitN(f.info, "\x00", 4)
	return fields[0], fields[1], fields[2], fields[3]
}

// keyedPattern is a pattern for the value of a key (a cookie, header or JS
// global name).
type keyedPattern struct {
	key     string
	pattern *ParsedPattern
}

// keyedPatterns are patterns for the value of a key (a meta name or DNS
// record type).
type keyedPatterns struct {
	key      string
	patterns []*ParsedPattern
}

// domRule matches elements matching a selector for which all checks pass.
type domRule struct {
	sel    *domSelector
	checks []domCheck // sorted by name
}

// domCheck is a check of an element: name is "exists", "text" or the name
// of an attribute. pattern is nil for "exists".
type domCheck struct {
	name    string
	pattern *ParsedPattern
}

// Name returns the name of the tech.
func (f *CompiledFingerprint) Name() string {
	return f.name
}

func (f *CompiledFingerprint) GetJSRules() map[string]*ParsedPattern {
	rules := make(map[string]*ParsedPattern, len(f.js))
	for _, kp := range f.js {
		rules[kp.key] = kp.pattern
	}
	return rules
}

func (f *CompiledFingerprint) GetDOMRules() map[string]map[string]*ParsedPattern {
	rules := make(map[string]map[string]*ParsedPattern, len(f.dom))
	for _, rule := range f.dom {
		checks := make(map[string]*ParsedPattern, len(rule.checks))
		for _, check := range rule.checks {
			checks[check.name] = check.pattern
		}
		rules[rule.sel.selector] = checks
	}
	return rules
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

// lookup returns the fingerprint of the named tech, or nil.
func (f *CompiledFingerprints) lookup(name string) *CompiledFingerprint {
	i := sort.Search(len(f.Apps), func(i int) bool { return f.Apps[i].name >= name })
	if i < len(f.Apps) && f.Apps[i].name == name {
		return f.Apps[i]
	}
	return nil
}

// literalMatcher returns the matcher for the prefilter literals of part, or
// nil if it has none.
func (f *CompiledFingerprints) literalMatcher(p part) *literalMatcher {
	f.literalMatchersOnce.Do(func() {
		lists := f.literalLists()
		f.literalMatchers = make(map[part]*literalMatcher)
		for p, lits := range map[part][]string{htmlPart: lists.html, cssPart: lists.css, robotsPart: lists.robots} {
			if m := newLiteralMatcher(lits); m != nil {
				f.literalMatchers[p] = m
			}
		}
	})
	return f.literalMatchers[p]
}

// hasJSGlobal reports whether name is a JS global used by a js pattern.
func (f *CompiledFingerprints) hasJSGlobal(name string) bool {
	f.jsGlobalsOnce.Do(func() {
		names := f.literalLists().jsGlobals
		f.jsGlobals = make(map[string]struct{}, len(names))
		for _, name := range names {
			f.jsGlobals[name] = struct{}{}
		}
	})
	_, ok := f.jsGlobals[name]
	return ok
}

// domLiteralMatcher returns the matcher for the literals of the dom
// selectors, or nil if they have none.
func (f *CompiledFingerprints) domLiteralMatcher() *literalMatcher {
	f.domLiteralsOnce.Do(func() {
		if f.domLiterals = newLiteralMatcher(f.literalLists().dom); f.domLiterals != nil {
			f.domLiterals.foldCase()
		}
	})
	return f.domLiterals
}

// matchString matches a string for the fingerprints
func (f *CompiledFingerprints) matchString(data string, part part, timeout time.Duration) []matchPartResult {
	var matched bool
	var technologies []matchPartResult

	// Lowercase once so each pattern's literal prefilter can rule the input
	// out without running the regex. ToLower doesn't allocate if data is
	// already lowercase, as the HTML body is.
	var has func(lit string) bool
	if lowered := strings.ToLower(data); !strings.Contains(lowered, foldHazard) {
		if len(lowered) >= minScanLen {
			if m := f.literalMatcher(part); m != nil {
				has = m.scan(lowered)
			}
		}
		if has == nil {
			has = func(lit string) bool { return strings.Contains(lowered, lit) }
		}
	}

	for _, fingerprint := range f.Apps {
		var version string
		confidence := 100

		var patterns []*ParsedPattern
		switch part {
		case jsPart:
			for _, kp := range fingerprint.js {
				patterns = append(patterns, kp.pattern)
			}
		case scriptPart:
			patterns = fingerprint.scriptSrc
		case htmlPart:
			patterns = fingerprint.html
		case robotsPart:
			patterns = fingerprint.robots
		case certIssuerPart:
			patterns = fingerprint.certIssuer
		case cssPart:
			// Use dedicated CSS patterns
			patterns = fingerprint.css
		}
		for _, pattern := range patterns {
			if has != nil && !pattern.mayMatch(has) {
				continue
			}
			if valid, versionString := pattern.Evaluate(data, timeout); valid {
				matched = true
				if version == "" && versionString != "" {
					version = versionString
				}
				confidence = pattern.Confidence
			}
		}

		// If no match, continue with the next fingerprint
		if !matched {
			continue
		}

		// Append the technologies as well as implied ones
		technologies = append(technologies, matchPartResult{
			application: fingerprint.name,
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

// keyedPatternsOf returns the patterns of fingerprint for part: cookiesPart,
// headersPart or metaPart.
//
// Note that jsPart has none: js patterns have never been matched this way
// (see the matchMapString call in pipeline.go), and matching them would
// change detections.
func keyedPatternsOf(fingerprint *CompiledFingerprint, part part) (single []keyedPattern, multi []keyedPatterns) {
	switch part {
	case cookiesPart:
		return fingerprint.cookies, nil
	case headersPart:
		return fingerprint.headers, nil
	case metaPart:
		return nil, fingerprint.meta
	}
	return nil, nil
}

// matchKeyValue matches a key-value store map for the fingerprints
func (f *CompiledFingerprints) matchKeyValueString(key, value string, part part, timeout time.Duration) []matchPartResult {
	return f.matchKeyValues(func(k string) (string, bool) {
		return value, k == key
	}, part, timeout)
}

// matchMapString matches a key-value store map for the fingerprints
func (f *CompiledFingerprints) matchMapString(keyValue map[string]string, part part, timeout time.Duration) []matchPartResult {
	return f.matchKeyValues(func(k string) (string, bool) {
		v, ok := keyValue[k]
		return v, ok
	}, part, timeout)
}

// matchKeyValues matches the values of keys, as reported by get, against
// the patterns of part.
func (f *CompiledFingerprints) matchKeyValues(get func(key string) (string, bool), part part, timeout time.Duration) []matchPartResult {
	var matched bool
	var technologies []matchPartResult

	for _, fingerprint := range f.Apps {
		var version string
		confidence := 100

		single, multi := keyedPatternsOf(fingerprint, part)
		for _, kp := range single {
			value, ok := get(kp.key)
			if !ok {
				continue
			}
			if valid, versionString := kp.pattern.Evaluate(value, timeout); valid {
				matched = true
				if version == "" && versionString != "" {
					version = versionString
				}
				confidence = kp.pattern.Confidence
				break
			}
		}
		for _, kp := range multi {
			value, ok := get(kp.key)
			if !ok {
				continue
			}
			for _, pattern := range kp.patterns {
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

		// If no match, continue with the next fingerprint
		if !matched {
			continue
		}

		technologies = append(technologies, matchPartResult{
			application: fingerprint.name,
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

	for _, fingerprint := range f.Apps {
		var version string
		confidence := 100

		// Skip if fingerprint has no DNS patterns
		if len(fingerprint.dns) == 0 {
			continue
		}

		for _, kp := range fingerprint.dns {
			recordValues, ok := dnsRecords[kp.key]
			if !ok {
				continue // No matching record type found
			}

			// Try to match any record value against any pattern for this record type
			for _, recordValue := range recordValues {
				for _, pattern := range kp.patterns {
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
			application: fingerprint.name,
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
	return assets.FingerprintsJSON
}
