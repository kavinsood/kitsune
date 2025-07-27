package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"regexp/syntax"
	"strings"
)

// --- JSON Normalization Helpers ---

// Compile patterns that are used repeatedly at the package level.
var (
	// Regex to match lookaround assertions (lookahead/lookbehind)
	lookaroundRegex = regexp.MustCompile(`\(\?[!<=][^)]*\)`)

	// Regex to match in-pattern backreferences (e.g., \1, \2, but not \\1)
	backreferenceRegex = regexp.MustCompile(`([^\\])\\([1-9])`)

	// Regex to count alphanumeric characters in patterns
	simpleCharCounter = regexp.MustCompile(`[a-zA-Z0-9]`)

	// Regex to match backreferences for removal (e.g., \1, \2, etc.)
	backrefRe = regexp.MustCompile(`\\([1-9][0-9]*)`)
)

// areParenthesesBalanced checks if parentheses are balanced in a regex string
func areParenthesesBalanced(s string) bool {
	balance := 0
	for _, r := range s {
		if r == '(' {
			balance++
		} else if r == ')' {
			balance--
		}
		if balance < 0 {
			return false
		}
	}
	return balance == 0
}

// SanitizeRegex attempts to fix common invalid regex constructs.
// It returns the cleaned regex and a boolean indicating if it's still valid.
func SanitizeRegex(rawRegex, appName string) (string, bool) {
	cleaned := rawRegex

	// Remove lookarounds
	if lookaroundRegex.MatchString(cleaned) {
		// log.Printf("INFO: Stripping unsupported lookaround from pattern for app '%s'. Original: `%s`", appName, cleaned)
		cleaned = lookaroundRegex.ReplaceAllString(cleaned, "")
	}

	// Remove backreferences
	if backreferenceRegex.MatchString(cleaned) {
		// log.Printf("INFO: Stripping unsupported backreference from pattern for app '%s'. Original: `%s`", appName, cleaned)
		cleaned = backreferenceRegex.ReplaceAllString(cleaned, "$1")
	}

	// Check for balanced parentheses
	if !areParenthesesBalanced(cleaned) {
		// log.Printf("WARN: Discarding structurally invalid pattern for app '%s' (unbalanced parentheses). Pattern: `%s`", appName, cleaned)
		return "", false
	}

	return cleaned, true
}

// NEW: Define a denylist of low-signal, common patterns.
// These should be checked as whole-word matches.
var patternDenylist = map[string]struct{}{
	"noscript": {},
	"script":   {},
	"meta":     {},
	"title":    {},
	"head":     {},
	"body":     {},
	"div":      {},
	"span":     {},
	"style":    {},
	"button":   {},
	"submit":   {},
	"login":    {},
	"admin":    {},
	"cart":     {},
	"http":     {},
	"https":    {},
	"paypal":   {},
	"react":    {}, // Too generic, needs more context like a version number.
	"vue":      {},
	"angular":  {},
	"jquery":   {},
	"svelte":   {}, // Too generic, needs more context like a version number or specific framework indicators
	"wagtail":  {}, // Too generic, needs more context like specific Wagtail indicators
}

const minPatternLength = 4 // A reasonable minimum length for a significant pattern.

// normalizePatternValue now uses SanitizeRegex
func normalizePatternValue(value interface{}, appName string) (*ParsedPattern, bool) {
	var raw string
	switch v := value.(type) {
	case string:
		raw = v
	case map[string]interface{}:
		if r, ok := v["regex"].(string); ok {
			raw = r
		}
	}
	if raw == "" {
		return nil, false
	}
	parsed, err := parseWappalyzerDSL(raw)
	if err != nil {
		return nil, false
	}
	cleanedRegex := cleanWappalyzerPatternAST(parsed.Regex)
	trimmedCleanedRegex := strings.TrimSpace(cleanedRegex)

	// --- UPGRADED Guardrails ---

	// 1. Check against the denylist.
	if _, isDenied := patternDenylist[strings.ToLower(trimmedCleanedRegex)]; isDenied {
		return nil, false
	}

	// 2. Check for trivial patterns (your existing check).
	if trimmedCleanedRegex == "" || trimmedCleanedRegex == ".*" || trimmedCleanedRegex == "." {
		return nil, false
	}

	// 3. Enforce minimum length. This is a powerful heuristic.
	// We use a regex to count user-visible characters, ignoring escapes and anchors.
	// This is a bit naive but better than a simple len().
	if len(simpleCharCounter.FindAllString(trimmedCleanedRegex, -1)) < minPatternLength {
		return nil, false
	}

	// Final validation check after cleaning
	if _, err := regexp.Compile(trimmedCleanedRegex); err != nil {
		return nil, false
	}

	parsed.Regex = trimmedCleanedRegex
	return parsed, true
}

// normalizePatternArray now handles arrays, single strings, and complex maps.
func normalizePatternArray(arr interface{}, appName string) []ParsedPattern {
	patterns := []ParsedPattern{}

	switch v := arr.(type) {
	case []interface{}:
		// This is the case you already handle: an array of patterns.
		for _, item := range v {
			if p, ok := normalizePatternValue(item, appName); ok {
				patterns = append(patterns, *p)
			}
		}
	case string:
		// NEW: Handle a single string pattern. Coerce it to a single-item array.
		if p, ok := normalizePatternValue(v, appName); ok {
			patterns = append(patterns, *p)
		}
	case map[string]interface{}:
		// NEW: Pragmatically handle complex DOM objects.
		// Extract the keys (CSS selectors) and treat them as patterns.
		// We discard the value (text/attribute checks) for now.
		for key := range v {
			if p, ok := normalizePatternValue(key, appName); ok {
				patterns = append(patterns, *p)
			}
		}
	case nil:
		// Do nothing.
	default:
		// The warning you were seeing. It's now handled by the cases above.
		fmt.Fprintf(os.Stderr, "[normalize] Unhandled pattern type for app %s, got %T: %#v\n", appName, arr, arr)
	}

	return patterns
}

// normalizePatternMap now takes appName for logging
func normalizePatternMap(m interface{}, appName string) map[string]ParsedPattern {
	out := map[string]ParsedPattern{}
	if m == nil {
		return out
	}
	if mm, ok := m.(map[string]interface{}); ok {
		for k, v := range mm {
			if p, ok := normalizePatternValue(v, appName); ok {
				out[k] = *p
			}
		}
	}
	return out
}

// normalizeMetaValue now takes appName for logging
func normalizeMetaValue(value interface{}, appName string) []ParsedPattern {
	patterns := []ParsedPattern{}
	switch v := value.(type) {
	case string, map[string]interface{}:
		if p, ok := normalizePatternValue(v, appName); ok {
			patterns = append(patterns, *p)
		}
	case []interface{}:
		for _, item := range v {
			if p, ok := normalizePatternValue(item, appName); ok {
				patterns = append(patterns, *p)
			}
		}
	}
	return patterns
}

// normalizeMetaMap now takes appName for logging
func normalizeMetaMap(m interface{}, appName string) map[string][]ParsedPattern {
	out := map[string][]ParsedPattern{}
	if m == nil {
		return out
	}
	if mm, ok := m.(map[string]interface{}); ok {
		for k, v := range mm {
			arr := normalizeMetaValue(v, appName)
			if len(arr) > 0 {
				out[k] = arr
			}
		}
	}
	return out
}

// --- AST Regex Cleaner (Corrected) ---

func cleanWappalyzerPatternAST(raw string) string {
	// 1. Remove Wappalyzer-specific metadata via string manipulation.
	// This is acceptable as it's a proprietary, non-standard extension.
	if idx := strings.Index(raw, "\\;version:"); idx != -1 {
		raw = raw[:idx]
	}
	if idx := strings.Index(raw, "\\;confidence:"); idx != -1 {
		raw = raw[:idx]
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	// 2. Remove backreferences (Go doesn't support them) using a robust regex.
	// Go's regexp/syntax does not define OpBackreference; it will fail to parse patterns with backreferences.
	// We must strip them at the string level, but only true backreferences (e.g., \1, \2, ...), not escaped backslashes.
	raw = backrefRe.ReplaceAllStringFunc(raw, func(m string) string {
		// fmt.Fprintf(os.Stderr, "[normalize] warning: removed unsupported backreference '%s' from pattern '%s'\n", m, raw)
		return ""
	})

	// 3. Parse the pattern into an AST. We use the Perl flag as it's the
	// most common and liberal syntax variant for web-based regexes.
	re, err := syntax.Parse(raw, syntax.Perl)
	if err != nil {
		// fmt.Fprintf(os.Stderr, "[normalize] warning: failed to parse regex '%s', skipping: %v\n", raw, err)
		return "" // Invalid from the start, discard it.
	}

	// 4. Define a recursive function to walk and transform the AST.
	var transform func(*syntax.Regexp) *syntax.Regexp
	transform = func(r *syntax.Regexp) *syntax.Regexp {
		// Recurse to transform all sub-expressions first.
		for i, sub := range r.Sub {
			r.Sub[i] = transform(sub)
		}
		// Simplify the AST by unwrapping capture groups. A capture group node (OpCapture)
		// is replaced by its contents. This effectively removes the capturing behavior
		// and the parentheses, e.g., a pattern like `(foo)` becomes `foo`.
		if r.Op == syntax.OpCapture && len(r.Sub) > 0 {
			// By returning the sub-expression, we remove the OpCapture node from the tree.
			return r.Sub[0]
		}
		return r
	}

	// 5. Apply the transformation to the entire tree and serialize back to a string.
	re = transform(re)
	return re.String()
}

// parseWappalyzerDSL parses a Wappalyzer DSL pattern string into a ParsedPattern struct.
func parseWappalyzerDSL(rawPattern string) (*ParsedPattern, error) {
	if rawPattern == "" {
		return nil, fmt.Errorf("raw pattern is empty")
	}

	// The separator in the file is `\;`. The backslash is an escape for the semicolon.
	// We split by this multi-character sequence.
	parts := strings.Split(rawPattern, `\;`)
	regexStr := parts[0]
	commands := make(map[string]string)

	if len(parts) > 1 {
		for _, part := range parts[1:] {
			// Split by the first colon only. e.g., "version:\\1"
			kv := strings.SplitN(part, ":", 2)
			if len(kv) == 2 {
				commands[kv[0]] = kv[1]
			}
		}
		// MAKE THE SUCCESS LOUD
		// if len(commands) > 0 {
		// 	log.Printf("OK: Found commands for pattern `%s`: %v", parts[0], commands)
		// }
	}

	return &ParsedPattern{
		Regex:    regexStr,
		Commands: commands,
	}, nil
}

// --- Main Normalization Entry Point ---

type rawFingerprints struct {
	Apps map[string]map[string]interface{} `json:"apps"`
}

func NormalizeFromBytes(f []byte) ([]byte, error) {
	var raw rawFingerprints
	if err := json.Unmarshal(f, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse raw data: %w", err)
	}
	out := Fingerprints{Apps: make(map[string]Fingerprint, len(raw.Apps))}
	for app, fp := range raw.Apps {
		outfp := Fingerprint{
			CSS:       normalizePatternArray(fp["css"], app),
			Cookies:   normalizePatternMap(fp["cookies"], app),
			JS:        normalizePatternMap(fp["js"], app),
			Headers:   normalizePatternMap(fp["headers"], app),
			HTML:      normalizePatternArray(fp["html"], app),
			Script:    normalizePatternArray(fp["scripts"], app),
			ScriptSrc: normalizePatternArray(fp["scriptSrc"], app),
			Meta:      normalizeMetaMap(fp["meta"], app),

			// --- New fields ---
			URL:        normalizePatternArray(fp["url"], app),
			Robots:     normalizePatternArray(fp["robots"], app),
			DOM:        normalizePatternArray(fp["dom"], app),
			DNS:        normalizePatternMap(fp["dns"], app),
			CertIssuer: normalizePatternMap(fp["certIssuer"], app),

			Implies:     nil,
			Cats:        nil,
			Description: "",
			Website:     "",
			Icon:        "",
			CPE:         "",
		}
		if v, ok := fp["implies"]; ok {
			switch vv := v.(type) {
			case []interface{}:
				for _, item := range vv {
					if s, ok := item.(string); ok {
						outfp.Implies = append(outfp.Implies, s)
					}
				}
			case string:
				outfp.Implies = append(outfp.Implies, vv)
			}
		}
		if v, ok := fp["cats"]; ok {
			switch vv := v.(type) {
			case []interface{}:
				for _, item := range vv {
					if f, ok := item.(float64); ok {
						outfp.Cats = append(outfp.Cats, int(f))
					}
				}
			case float64:
				outfp.Cats = append(outfp.Cats, int(vv))
			}
		}
		if v, ok := fp["description"].(string); ok {
			outfp.Description = v
		}
		if v, ok := fp["website"].(string); ok {
			outfp.Website = v
		}
		if v, ok := fp["icon"].(string); ok {
			outfp.Icon = v
		}
		if v, ok := fp["cpe"].(string); ok {
			outfp.CPE = v
		}
		out.Apps[app] = outfp
	}
	return json.MarshalIndent(out, "", "  ")
}

func Normalize(rawJSONPath string) ([]byte, error) {
	f, err := os.ReadFile(rawJSONPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", rawJSONPath, err)
	}
	return NormalizeFromBytes(f)
}
