package profiler

import (
	"encoding/json"
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

// Fingerprint is a single piece of information about a tech validated and normalized.
//
// Robots, XHR and Probe need requests a static scan doesn't make, so they are
// not compiled. RequiresCategory lists category ids, one of which a detected
// tech must have for this tech to be detected.
type Fingerprint struct {
	Cats             []int                             `json:"cats"`
	CSS              []string                          `json:"css"`
	Cookies          map[string]string                 `json:"cookies"`
	Dom              map[string]map[string]interface{} `json:"dom"`
	JS               map[string]string                 `json:"js"`
	Headers          map[string]string                 `json:"headers"`
	HTML             []string                          `json:"html"`
	Script           []string                          `json:"scripts"`
	ScriptSrc        []string                          `json:"scriptSrc"`
	Meta             map[string][]string               `json:"meta"`
	DNS              map[string][]string               `json:"dns"`
	Robots           []string                          `json:"robots"`
	CertIssuer       []string                          `json:"certIssuer"`
	Text             []string                          `json:"text"`
	URL              []string                          `json:"url"`
	XHR              []string                          `json:"xhr"`
	Probe            json.RawMessage                   `json:"probe,omitempty"`
	Implies          []string                          `json:"implies"`
	Requires         []string                          `json:"requires"`
	RequiresCategory []int                             `json:"requiresCategory"`
	Excludes         []string                          `json:"excludes"`
	Description      string                            `json:"description"`
	Website          string                            `json:"website"`
	CPE              string                            `json:"cpe"`
	Icon             string                            `json:"icon"`
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

	// jsGlobalTechs holds the techs whose js patterns can be evaluated
	// statically, by global (see jsGlobals). Built on first use.
	jsGlobalsOnce sync.Once
	jsGlobalTechs map[string][]jsTech

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
	// implies contains technologies that are implicit with this tech, with
	// their wappalyzer modifiers (see parseImplied)
	implies []string
	// requires and requiresCategory gate the tech: if either is set, it is
	// only detected if one of the named techs, or a tech in one of the
	// categories, is detected too.
	requires         []string
	requiresCategory []int
	// excludes contains technologies whose detection this tech overrides
	excludes []string
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
	// certIssuer contains fingerprints for TLS certificate issuers
	certIssuer []*ParsedPattern
	// css contains fingerprints for CSS content
	css []*ParsedPattern
	// text contains fingerprints for the visible text of the page
	text []*ParsedPattern
	// url contains fingerprints for the URL of the page
	url []*ParsedPattern
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

// domRule is a dom selector with checks of the elements it finds. Each
// check is a detection of its own: they are not combined.
type domRule struct {
	sel    *domSelector
	checks []domCheck // sorted by name
}

// domCheck is a check of an element: name is "exists", "text" or the name
// of an attribute. For "exists" the pattern only carries the confidence and
// version of the detection.
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
	scriptPart // the content of inline and fetched scripts
	scriptSrcPart
	metaPart
	dnsPart
	certIssuerPart
	cssPart
	textPart
	urlPart
	domPart
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
// nil if it has none. Only the parts matched against large inputs have
// one.
func (f *CompiledFingerprints) literalMatcher(p part) *literalMatcher {
	f.literalMatchersOnce.Do(func() {
		lists := f.literalLists()
		f.literalMatchers = make(map[part]*literalMatcher)
		for p, lits := range map[part][]string{htmlPart: lists.html, scriptPart: lists.script, cssPart: lists.css, textPart: lists.text} {
			if m := newLiteralMatcher(lits); m != nil {
				f.literalMatchers[p] = m
			}
		}
	})
	return f.literalMatchers[p]
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

// patternsOf returns the patterns of fingerprint for a part matched
// against single strings.
func patternsOf(fingerprint *CompiledFingerprint, part part) []*ParsedPattern {
	switch part {
	case htmlPart:
		return fingerprint.html
	case scriptPart:
		return fingerprint.script
	case scriptSrcPart:
		return fingerprint.scriptSrc
	case certIssuerPart:
		return fingerprint.certIssuer
	case cssPart:
		return fingerprint.css
	case textPart:
		return fingerprint.text
	case urlPart:
		return fingerprint.url
	}
	return nil
}

// matchString matches data against the patterns of part, returning a
// result for every pattern that matches.
func (f *CompiledFingerprints) matchString(data string, part part, timeout time.Duration) []matchPartResult {
	var technologies []matchPartResult

	// Lowercase once so each pattern's literal prefilter can rule the input
	// out without running the regex.
	lowered := prefilterInput(data)
	var has func(lit string) bool
	if len(lowered) >= minScanLen {
		if m := f.literalMatcher(part); m != nil {
			has = m.scan(lowered)
		}
	}
	if has == nil {
		has = func(lit string) bool { return strings.Contains(lowered, lit) }
	}

	for _, fingerprint := range f.Apps {
		for _, pattern := range patternsOf(fingerprint, part) {
			if !pattern.mayMatch(has) {
				continue
			}
			if valid, version := pattern.Evaluate(data, timeout); valid {
				technologies = append(technologies, newMatch(fingerprint.name, pattern, version))
			}
		}
	}
	return technologies
}

// matchKeyValues matches values, keyed by lowercase name, against the
// patterns of part: cookiesPart, headersPart, metaPart or dnsPart. It
// returns a result for every pattern matching a value of its key. A pattern
// key ending in "*" matches every name it prefixes, as for wappalyzer's
// "_ga_*" cookie.
func (f *CompiledFingerprints) matchKeyValues(values map[string][]string, part part, timeout time.Duration) []matchPartResult {
	if len(values) == 0 {
		return nil
	}
	var technologies []matchPartResult
	match := func(fingerprint *CompiledFingerprint, key string, patterns ...*ParsedPattern) {
		for _, value := range valuesOf(values, key) {
			for _, pattern := range patterns {
				if valid, version := pattern.Evaluate(value, timeout); valid {
					technologies = append(technologies, newMatch(fingerprint.name, pattern, version))
				}
			}
		}
	}
	for _, fingerprint := range f.Apps {
		switch part {
		case cookiesPart, headersPart:
			kps := fingerprint.cookies
			if part == headersPart {
				kps = fingerprint.headers
			}
			for _, kp := range kps {
				match(fingerprint, kp.key, kp.pattern)
			}
		case metaPart, dnsPart:
			kps := fingerprint.meta
			if part == dnsPart {
				kps = fingerprint.dns
			}
			for _, kp := range kps {
				match(fingerprint, kp.key, kp.patterns...)
			}
		}
	}
	return technologies
}

// valuesOf returns the values of key, or of every name it prefixes if it
// ends in "*".
func valuesOf(values map[string][]string, key string) []string {
	prefix, wildcard := strings.CutSuffix(key, "*")
	if !wildcard || prefix == "" {
		return values[key]
	}
	var out []string
	for name, vs := range values {
		if strings.HasPrefix(name, prefix) {
			out = append(out, vs...)
		}
	}
	return out
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
