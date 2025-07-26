package kitsune

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// PatternInfo associates a compiled pattern with its owning application
// and any additional metadata if needed in the future.
type PatternInfo struct {
	Pattern  *regexp.Regexp
	AppName  string
	Commands map[string]string // Carry the commands
}

// Detection holds extracted information for a detected app (e.g., version)
type Detection struct {
	Version string
	// Add Confidence, etc. later

	// --- NEW: Audit Trail Fields ---
	DetectedBy     string // The vector, e.g., "html", "header:Server", "cookie:sessionid"
	MatchedPattern string // The regex that triggered the match
	MatchedValue   string // The specific value that was matched against

	// --- NEW: Confidence Score ---
	Confidence ConfidenceLevel
}

type ConfidenceLevel int

const (
	ConfidenceLow ConfidenceLevel = iota
	ConfidenceMedium
	ConfidenceHigh
)

// EfficientMatcher holds context-centric pattern slices/maps for efficient matching.
type EfficientMatcher struct {
	HTMLPatterns      []PatternInfo
	ScriptSrcPatterns []PatternInfo
	HeaderPatterns    map[string][]PatternInfo // key is header name
	CookiePatterns    map[string][]PatternInfo // key is cookie name
	MetaPatterns      map[string][]PatternInfo // key is meta name
	ScriptPatterns    []PatternInfo
	JSPatterns        map[string][]PatternInfo // key is JS variable name
	CSSPatterns       []PatternInfo

	// --- NEW FIELDS ---
	URLPatterns        []PatternInfo
	RobotsPatterns     []PatternInfo
	DOMPatterns        []PatternInfo            // Pattern.String() will be a CSS selector
	DNSPatterns        map[string][]PatternInfo // key: "TXT", "MX" etc.
	CertIssuerPatterns map[string][]PatternInfo // key: "commonName" etc. (simplified)
}

// AnalysisData holds all the raw data collected for a single analysis run.
type AnalysisData struct {
	TargetURL     string
	MainResponse  *http.Response
	RobotsContent []byte
	DNSRecords    map[string][]string // e.g. {"TXT": ["..."], "MX": ["..."]}
	CertIssuer    string
	Body          []byte
	PageData      *PageData
}

// PageData holds extracted data from a web page.
type PageData struct {
	ScriptSrcs    []string
	MetaContent   map[string][]string
	InlineScripts []string
	InlineCSS     []string
	VisibleText   string
	Title         string
	RawBody       []byte
	GoQueryDoc    *goquery.Document
}

// extractVersion processes versioning commands against regex submatches.
func extractVersion(commands map[string]string, submatches []string) string {
	versionCmd, ok := commands["version"]
	if !ok || versionCmd == "" || len(submatches) <= 1 {
		return ""
	}

	// Wappalyzer uses \1, \2 etc. for submatch indices.
	if strings.HasPrefix(versionCmd, `\`) {
		// A simple TrimPrefix and Atoi is more robust than Sscanf.
		idxStr := strings.TrimPrefix(versionCmd, `\`)
		if versionIndex, err := strconv.Atoi(idxStr); err == nil {
			if len(submatches) > versionIndex {
				return submatches[versionIndex]
			}
		}
	}
	// Handle other potential version command formats here if needed.
	return ""
}

func matchHeaders(k *Kitsune, headers http.Header, detected map[string]Detection) {
	matcher := k.matcher
	for headerKey, values := range headers {
		patterns, ok := matcher.HeaderPatterns[strings.ToLower(headerKey)]
		if !ok {
			continue
		}
		for _, pi := range patterns {
			for _, value := range values {
				submatches := matchWithTimeout(pi.Pattern, []byte(value), k.RegexTimeout)
				if submatches != nil {
					result := Detection{
						Version:        extractVersion(pi.Commands, submatches),
						DetectedBy:     "header:" + headerKey,
						MatchedPattern: pi.Pattern.String(),
						MatchedValue:   submatches[0],
						Confidence:     ConfidenceHigh, // Headers are strong signals
					}
					detected[pi.AppName] = result
					break
				}
			}
		}
	}
}

func matchCookies(k *Kitsune, headers http.Header, detected map[string]Detection) {
	matcher := k.matcher
	setCookieHeaders := headers["Set-Cookie"]
	parsedCookies := make(map[string]string)
	for _, raw := range setCookieHeaders {
		cookie, err := http.ParseSetCookie(raw)
		if err == nil && cookie != nil && cookie.Name != "" {
			name := strings.ToLower(strings.TrimSpace(cookie.Name))
			parsedCookies[name] = cookie.Value
		}
	}
	for cookieKey, value := range parsedCookies {
		patterns, ok := matcher.CookiePatterns[cookieKey]
		if !ok {
			continue
		}
		for _, pi := range patterns {
			submatches := matchWithTimeout(pi.Pattern, []byte(value), k.RegexTimeout)
			if submatches != nil {
				result := Detection{
					Version:        extractVersion(pi.Commands, submatches),
					DetectedBy:     "cookie:" + cookieKey,
					MatchedPattern: pi.Pattern.String(),
					MatchedValue:   submatches[0],
					Confidence:     ConfidenceHigh, // Cookies are strong signals
				}
				detected[pi.AppName] = result
				break
			}
		}
	}
}

func matchScriptSrc(k *Kitsune, pageData *PageData, detected map[string]Detection) {
	matcher := k.matcher
	inputs := make([][]byte, len(pageData.ScriptSrcs))
	for i, src := range pageData.ScriptSrcs {
		inputs[i] = []byte(src)
	}
	for _, pi := range matcher.ScriptSrcPatterns {
		for _, input := range inputs {
			submatches := matchWithTimeout(pi.Pattern, input, k.RegexTimeout)
			if submatches != nil {
				result := Detection{
					Version:        extractVersion(pi.Commands, submatches),
					DetectedBy:     "scriptSrc",
					MatchedPattern: pi.Pattern.String(),
					MatchedValue:   submatches[0],
					Confidence:     ConfidenceHigh, // Script sources are strong signals
				}
				detected[pi.AppName] = result
				break
			}
		}
	}
}

func matchMeta(k *Kitsune, pageData *PageData, detected map[string]Detection) {
	matcher := k.matcher
	for metaKey, contents := range pageData.MetaContent {
		lowerMetaKey := strings.ToLower(metaKey)

		patterns, ok := matcher.MetaPatterns[lowerMetaKey]
		if !ok {
			continue
		}

		for _, pi := range patterns {

			for _, content := range contents {
				submatches := matchWithTimeout(pi.Pattern, []byte(content), k.RegexTimeout)

				if submatches != nil {
					result := Detection{
						Version:        extractVersion(pi.Commands, submatches),
						DetectedBy:     "meta:" + metaKey,
						MatchedPattern: pi.Pattern.String(),
						MatchedValue:   submatches[0],
						Confidence:     ConfidenceMedium, // Meta tags are medium confidence
					}
					detected[pi.AppName] = result
					break
				}
			}
		}
	}
}

func matchScript(k *Kitsune, pageData *PageData, detected map[string]Detection) {
	matcher := k.matcher
	// Match against each inline <script> block only (context-aware, not RawBody)
	for _, pi := range matcher.ScriptPatterns {
		if _, exists := detected[pi.AppName]; exists {
			continue // Already found.
		}
		// Match against each inline script block
		for _, scriptContent := range pageData.InlineScripts {
			submatches := matchWithTimeout(pi.Pattern, []byte(scriptContent), k.RegexTimeout)
			if submatches != nil {
				result := Detection{
					Version:        extractVersion(pi.Commands, submatches),
					DetectedBy:     "script",
					MatchedPattern: pi.Pattern.String(),
					MatchedValue:   submatches[0],
					Confidence:     ConfidenceMedium, // Inline scripts are medium confidence
				}
				detected[pi.AppName] = result
				break // Found in one script, no need to check others for this app
			}
		}
	}
}

func matchHTML(k *Kitsune, pageData *PageData, detected map[string]Detection) {
	matcher := k.matcher
	// Use the extracted visible text only (context-aware, not RawBody)
	input := []byte(pageData.VisibleText)
	for _, pi := range matcher.HTMLPatterns {
		if _, exists := detected[pi.AppName]; exists {
			continue
		}
		submatches := matchWithTimeout(pi.Pattern, input, k.RegexTimeout)
		if submatches != nil {
			// --- THIS IS THE CHANGE ---
			// Instead of an empty struct, populate the audit trail.
			result := Detection{
				Version:        extractVersion(pi.Commands, submatches),
				DetectedBy:     "html",
				MatchedPattern: pi.Pattern.String(),
				MatchedValue:   submatches[0], // The full string that matched
				Confidence:     ConfidenceLow, // HTML body text is a weak signal
			}
			detected[pi.AppName] = result
		}
	}
}

// Heuristic regexes for extracting variable assignments from JavaScript code.
// ----------------------------------------------------------------------------------
// WARNING: These regexes are a pragmatic hack. They are intentionally simple and will
// fail on minified, packed, or complex JS syntax. This is a "flashlight" approach,
// not a full parser. Do NOT attempt to perfect these regexes—JavaScript's syntax is
// too complex for regex to handle robustly. Accept the limitations: these will only
// work for straightforward assignments in reasonably formatted code.
// Adding a proper JS parser would be overkill for our use case; this heuristic is a
// deliberate tradeoff for simplicity and speed.
// ----------------------------------------------------------------------------------
// Pre-compiled regex for JS property assignments (supports nested keys, strings, numbers, booleans)
var jsPropertyExtractor = regexp.MustCompile(`([a-zA-Z0-9_$.]+)\s*[:=]\s*(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)"|` + "`" + `((?:[^` + "`" + `\\]|\\.)*)` + "`" + `|([0-9.]+)|(true|false))\b`)

func matchJS(k *Kitsune, pageData *PageData, detected map[string]Detection) {
	if len(k.matcher.JSPatterns) == 0 {
		return // No JS patterns to match, so don't even scan.
	}

	for _, script := range pageData.InlineScripts {
		// Use the new, more powerful regex
		allMatches := jsPropertyExtractor.FindAllStringSubmatch(script, -1)

		for _, match := range allMatches {
			if len(match) < 3 {
				continue
			}

			// Group 1 is the full property path, e.g., "React.version"
			jsKey := match[1]
			var value string

			// Find the first non-empty value capture group (from 2 onwards)
			for i := 2; i < len(match); i++ {
				if match[i] != "" {
					value = match[i]
					break
				}
			}

			if value == "" {
				continue // Should not happen if regex is correct, but a good safeguard.
			}

			// The core logic remains: check if a pattern exists for this key.
			if patterns, ok := k.matcher.JSPatterns[jsKey]; ok {
				for _, pi := range patterns {
					submatches := matchWithTimeout(pi.Pattern, []byte(value), k.RegexTimeout)
					if submatches != nil {
						result := Detection{
							Version:        extractVersion(pi.Commands, submatches),
							DetectedBy:     "js:" + jsKey,
							MatchedPattern: pi.Pattern.String(),
							MatchedValue:   submatches[0],
							Confidence:     ConfidenceHigh, // JS variable matches are strong signals
						}
						detected[pi.AppName] = result
						break // Found a match for this key, move to the next key.
					}
				}
			}
		}
	}
}

// matchCSS scans inline CSS content for known patterns.
func matchCSS(k *Kitsune, pageData *PageData, detected map[string]Detection) {
	matcher := k.matcher
	for _, cssBlock := range pageData.InlineCSS {
		for _, pi := range matcher.CSSPatterns {
			if _, exists := detected[pi.AppName]; exists {
				continue
			}
			submatches := matchWithTimeout(pi.Pattern, []byte(cssBlock), k.RegexTimeout)
			if submatches != nil {
				result := Detection{
					Version:        extractVersion(pi.Commands, submatches),
					DetectedBy:     "css",
					MatchedPattern: pi.Pattern.String(),
					MatchedValue:   submatches[0],
					Confidence:     ConfidenceMedium, // CSS patterns are medium confidence
				}
				detected[pi.AppName] = result
			}
		}
	}
}

// --- NEW MATCHERS ---

func matchURL(k *Kitsune, data *AnalysisData, detected map[string]Detection) {
	for _, pi := range k.matcher.URLPatterns {
		submatches := matchWithTimeout(pi.Pattern, []byte(data.TargetURL), k.RegexTimeout)
		if submatches != nil {
			detected[pi.AppName] = Detection{
				Version:        extractVersion(pi.Commands, submatches),
				DetectedBy:     "url",
				MatchedPattern: pi.Pattern.String(),
				MatchedValue:   submatches[0],
				Confidence:     ConfidenceMedium, // URL patterns are medium confidence
			}
		}
	}
}

func matchRobots(k *Kitsune, data *AnalysisData, detected map[string]Detection) {
	if data.RobotsContent == nil {
		return
	}
	for _, pi := range k.matcher.RobotsPatterns {
		submatches := matchWithTimeout(pi.Pattern, data.RobotsContent, k.RegexTimeout)
		if submatches != nil {
			detected[pi.AppName] = Detection{
				Version:        extractVersion(pi.Commands, submatches),
				DetectedBy:     "robots",
				MatchedPattern: pi.Pattern.String(),
				MatchedValue:   submatches[0],
				Confidence:     ConfidenceMedium, // Robots.txt patterns are medium confidence
			}
		}
	}
}

// matchDOM uses CSS selectors for matching, not regex.
func matchDOM(k *Kitsune, data *AnalysisData, detected map[string]Detection) {
	if data.PageData == nil || data.PageData.GoQueryDoc == nil {
		return
	}
	doc := data.PageData.GoQueryDoc
	for _, pi := range k.matcher.DOMPatterns {
		// Here, the pattern's "regex" string is actually a CSS selector.
		selector := pi.Pattern.String()
		if doc.Find(selector).Length() > 0 {
			// DOM patterns rarely have version info, so we use an empty Detection struct.
			detected[pi.AppName] = Detection{
				DetectedBy:     "dom",
				MatchedPattern: selector,
				MatchedValue:   "CSS selector matched",
				Confidence:     ConfidenceLow, // DOM patterns are low confidence (even after filtering)
			}
		}
	}
}

func matchDNS(k *Kitsune, data *AnalysisData, detected map[string]Detection) {
	if data.DNSRecords == nil {
		return
	}
	for recordType, patterns := range k.matcher.DNSPatterns {
		if records, ok := data.DNSRecords[recordType]; ok {
			for _, pi := range patterns {
				for _, record := range records {
					submatches := matchWithTimeout(pi.Pattern, []byte(record), k.RegexTimeout)
					if submatches != nil {
						detected[pi.AppName] = Detection{
							Version:        extractVersion(pi.Commands, submatches),
							DetectedBy:     "dns:" + recordType,
							MatchedPattern: pi.Pattern.String(),
							MatchedValue:   submatches[0],
							Confidence:     ConfidenceHigh, // DNS records are strong signals
						}
						break // Found a match for this app, move to next pattern
					}
				}
			}
		}
	}
}

func matchCertIssuer(k *Kitsune, data *AnalysisData, detected map[string]Detection) {
	if data.CertIssuer == "" {
		return
	}
	// The key in the map is not used for now, we just loop through all cert patterns.
	for _, patterns := range k.matcher.CertIssuerPatterns {
		for _, pi := range patterns {
			submatches := matchWithTimeout(pi.Pattern, []byte(data.CertIssuer), k.RegexTimeout)
			if submatches != nil {
				detected[pi.AppName] = Detection{
					Version:        extractVersion(pi.Commands, submatches),
					DetectedBy:     "certIssuer",
					MatchedPattern: pi.Pattern.String(),
					MatchedValue:   submatches[0],
					Confidence:     ConfidenceHigh, // Certificate issuer is a strong signal
				}
			}
		}
	}
}

// --- UPDATED runAllMatchers ---
func runAllMatchers(k *Kitsune, data *AnalysisData, detected map[string]Detection) {
	// New matchers first
	matchURL(k, data, detected)
	matchRobots(k, data, detected)
	matchDNS(k, data, detected)
	matchCertIssuer(k, data, detected)

	// Existing matchers now take AnalysisData
	if data.MainResponse != nil {
		matchHeaders(k, data.MainResponse.Header, detected)
		matchCookies(k, data.MainResponse.Header, detected)
	}

	if data.PageData != nil {
		matchScriptSrc(k, data.PageData, detected)
		matchMeta(k, data.PageData, detected)
		matchScript(k, data.PageData, detected)
		matchHTML(k, data.PageData, detected)
		matchJS(k, data.PageData, detected)
		matchCSS(k, data.PageData, detected)
		matchDOM(k, data, detected) // Call the new DOM matcher
	}
}
