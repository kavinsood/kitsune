package profiler

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// JSGlobals is a map of global JavaScript variables and their values
type JSGlobals map[string]string

// JSExtractionResult contains extracted JavaScript globals and classes
type JSExtractionResult struct {
	// HighConfidence contains global variables with high confidence
	HighConfidence JSGlobals
	// LowConfidence contains global variables with lower confidence
	LowConfidence JSGlobals
	// PropertyPaths contains property paths like 'angular.version.full'
	PropertyPaths JSGlobals
	// Classes contains CSS classes added via JavaScript
	Classes []string
	// DetectedLibraries contains directly detected libraries with potential versions
	DetectedLibraries map[string]string
}

// Regular expressions for extracting JavaScript globals
var (
	// Direct variable declarations
	varDeclPattern = mustCompilePrefiltered(`(?:var|let|const)\s+([a-zA-Z0-9_$]+)\s*=\s*([^;]+)`)

	// Window assignments
	windowAssignPattern = mustCompilePrefiltered(`(?:window|self|top|global)\s*\.\s*([a-zA-Z0-9_$]+)\s*=\s*([^;]+)`)

	// Global this assignments
	thisAssignPattern = mustCompilePrefiltered(`this\s*\.\s*([a-zA-Z0-9_$]+)\s*=\s*([^;]+)`)

	// Direct global assignments (without var/let/const)
	globalAssignPattern = regexp.MustCompile(`^([a-zA-Z0-9_$]+)\s*=\s*([^;]+)`)

	// Property path assignments (enhanced to capture more formats)
	propPathPattern = regexp.MustCompile(`([a-zA-Z0-9_$]+(?:\.[a-zA-Z0-9_$]+){1,})\s*=\s*(?:['"]?(.*?)['"]?|([0-9][0-9.a-zA-Z_-]+)|true|false|null|undefined)`)

	// Property access patterns (for detection in conditions, function calls, etc.)
	propAccessPattern = regexp.MustCompile(`\b([a-zA-Z0-9_$]+(?:\.[a-zA-Z0-9_$]+){1,})\b`)

	// Object property access for version detection
	versionPropPattern = regexp.MustCompile(`\.version\s*=\s*['"]([0-9.]+)['"]`)

	// Class additions
	classAddPattern = mustCompilePrefiltered(`(?:classList|className)\s*\.\s*(?:add|toggle)\s*\(\s*['"]([^'"]+)['"]\s*\)`)

	// Version extraction with more flexible patterns
	versionPattern       = regexp.MustCompile(`([0-9]+(?:\.[0-9]+)+)`)
	versionSemverPattern = regexp.MustCompile(`['"](\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9.-]+)?)['"]`)

	// Enhanced library patterns for direct detection
	libraryPatterns = map[string]*prefilteredRegexp{
		// jQuery detection patterns
		"jQuery": mustCompilePrefiltered(`(?:jQuery|\$)(?:\.fn|\.prototype)?\.(?:jquery|version)\s*=\s*['"]([^'"]+)['"]`),

		// Angular framework detection patterns
		"AngularJS": mustCompilePrefiltered(`(?:angular(?:\.module|\.(version|bootstrap))|ng\.(module|directive))\b`),
		"Angular":   mustCompilePrefiltered(`(?:ng\.(?:platformBrowserDynamic|core)|@angular)\b`),

		// React framework detection
		"React": mustCompilePrefiltered(`(?:React(?:\.version\s*=\s*['"]([^'"]+)['"]|\.[a-zA-Z]+\s*=)|react(?:Dom|DOM)(?:\.[a-zA-Z]+)?)`),

		// Vue framework detection
		"Vue": mustCompilePrefiltered(`(?:Vue(?:\.version\s*=\s*['"]([^'"]+)['"]|\.component|\.[a-zA-Z]+\s*=)|createApp\s*\(|Vue\.createApp\s*\(|VueRouter\b)`),

		// UI frameworks and libraries
		"Modernizr":   mustCompilePrefiltered(`Modernizr(?:._version\s*=\s*['"]([^'"]+)['"]|\.[a-zA-Z]+\b)`),
		"Bootstrap":   mustCompilePrefiltered(`(?:bootstrap\.(?:VERSION|Modal)|(?:\.|\s+)(?:modal|carousel|collapse|dropdown|tooltip|popover|tab|alert|button)\()`),
		"Tailwind":    mustCompilePrefiltered(`tailwind(?:\.config|CSS)`),
		"Material-UI": mustCompilePrefiltered(`(?:MaterialUI|MUI|material-ui|@mui/material)\b`),

		// JS frameworks and libraries
		"Backbone":   mustCompilePrefiltered(`Backbone(?:\.VERSION\s*=\s*['"]([^'"]+)['"]|\.(?:Model|View|Router|Collection)\b)`),
		"Ember":      mustCompilePrefiltered(`Ember(?:\.VERSION\s*=\s*['"]([^'"]+)['"]|\.(?:Application|Component|Object)\b)`),
		"Prototype":  mustCompilePrefiltered(`Prototype(?:\.Version\s*=\s*['"]([^'"]+)['"]|\.\$)`),
		"MooTools":   mustCompilePrefiltered(`MooTools(?:\.version\s*=\s*['"]([^'"]+)['"]|\.[a-zA-Z]+\b)`),
		"Dojo":       mustCompilePrefiltered(`dojo(?:\.version(?:\s*=|\.toString)|\\.(?:declare|require|connect))`),
		"Lodash":     mustCompilePrefiltered(`_\.(?:VERSION|forEach|map|filter|find|debounce|throttle)\b`),
		"Underscore": mustCompilePrefiltered(`_\.(?:VERSION|each|map|reduce|filter|find|debounce|throttle)\b`),

		// Payment services and APIs
		"Stripe": mustCompilePrefiltered(`(?:Stripe\.version\s*=\s*['"]([^'"]+)['"]|Stripe\.(?:setPublishableKey|elements|createToken))`),
		"PayPal": mustCompilePrefiltered(`(?:paypal\.Buttons|PAYPAL\.apps\.(?:MiniCart|ButtonFactory))`),

		// State management
		"Redux": mustCompilePrefiltered(`(?:createStore|combineReducers|applyMiddleware|bindActionCreators)\b`),
		"MobX":  mustCompilePrefiltered(`(?:mobx|observable|computed|action|autorun|reaction)\b`),

		// Analytics and tracking
		"Google Analytics":   mustCompilePrefiltered(`ga\s*\(\s*['"](?:create|send|set)['"]|GoogleAnalyticsObject|gtag`),
		"Google Tag Manager": mustCompilePrefiltered(`gtm\.|googletagmanager\.com`),

		// Testing frameworks
		"Jest":  mustCompilePrefiltered(`(?:jest\.|describe\s*\(\s*['"][^'"]+['"]\s*,\s*\(?function)`),
		"Mocha": mustCompilePrefiltered(`(?:mocha\.|describe\s*\(\s*['"][^'"]+['"]\s*,\s*\(?function)`),

		// Build tools and bundlers visible in runtime
		"Webpack": mustCompilePrefiltered(`(?:__webpack_require__|webpackJsonp)`),
		"Babel":   mustCompilePrefiltered(`babelHelpers`),

		// Utility libraries
		"Moment.js": mustCompilePrefiltered(`moment(?:\.version|\(|\.\w+\()`),
		"Axios":     mustCompilePrefiltered(`axios(?:\.(?:get|post|put|delete|patch|request|interceptors))?`),
	}
)

// libraryLiterals finds the prefilter literals of all libraryPatterns.
var libraryLiterals = func() *literalMatcher {
	var lits []string
	for _, pattern := range libraryPatterns {
		for _, set := range pattern.literals {
			lits = append(lits, set...)
		}
	}
	return newLiteralMatcher(lits)
}()

// SplitIntoStatements breaks JavaScript code into individual statements.
//
// NOTE: This is a HEURISTIC, not a spec-compliant JavaScript parser. Its goal
// is to quickly split common JS code for pattern matching, not to perfectly
// parse all edge cases. It correctly handles semicolons within strings and
// ignores comments, but may fail on complex code involving things like
// semicolons inside of regex literals or advanced template literal usage.
// This is an intentional trade-off for performance and simplicity.
func SplitIntoStatements(js string) []string {
	var statements []string

	// Statements are returned as substrings of js rather than copies. The
	// original decoded js rune by rune, so invalid UTF-8 bytes came out as
	// U+FFFD; converting up front keeps that behaviour.
	if !utf8.ValidString(js) {
		js = string([]rune(js))
	}
	start := 0 // start of the current statement

	// Track string contexts and state
	inSingleQuote := false
	inDoubleQuote := false
	inTemplate := false
	inLineComment := false
	inBlockComment := false
	escaped := false

	// Process each character
	for i := 0; i < len(js); {
		r, width := utf8.DecodeRuneInString(js[i:])
		// We'll increment i at the end of each iteration

		// Handle escaping within strings
		if escaped {
			escaped = false
			i += width
			continue
		}

		// Check for escape character
		if (inSingleQuote || inDoubleQuote || inTemplate) && r == '\\' {
			escaped = true
			i += width
			continue
		}

		// Handle string boundaries
		switch {
		case r == '"' && !inSingleQuote && !inTemplate && !inLineComment && !inBlockComment:
			inDoubleQuote = !inDoubleQuote
		case r == '\'' && !inDoubleQuote && !inTemplate && !inLineComment && !inBlockComment:
			inSingleQuote = !inSingleQuote
		case r == '`' && !inSingleQuote && !inDoubleQuote && !inLineComment && !inBlockComment:
			inTemplate = !inTemplate
		}

		// Handle comments
		if !inSingleQuote && !inDoubleQuote && !inTemplate {
			// Start of line comment
			if r == '/' && i+1 < len(js) && js[i+1] == '/' && !inBlockComment {
				inLineComment = true
			}

			// End of line comment
			if (r == '\n' || r == '\r') && inLineComment {
				inLineComment = false
			}

			// Start of block comment
			if r == '/' && i+1 < len(js) && js[i+1] == '*' && !inLineComment {
				inBlockComment = true
			}

			// End of block comment
			if r == '/' && i > 0 && js[i-1] == '*' && inBlockComment {
				inBlockComment = false
			}
		}

		// Check for statement end
		if r == ';' && !inSingleQuote && !inDoubleQuote && !inTemplate && !inLineComment && !inBlockComment {
			i += width
			stmt := strings.TrimSpace(js[start:i])
			if stmt != "" && stmt != ";" {
				statements = append(statements, stmt)
			}
			start = i
			continue
		}

		// Move to the next rune
		i += width
	}

	// Add the last statement if there's content
	lastStatement := strings.TrimSpace(js[start:])
	if lastStatement != "" {
		statements = append(statements, lastStatement)
	}

	return statements
}

// isPropPathChar reports whether c can be part of a property path matched by
// propPathPattern or propAccessPattern.
func isPropPathChar(c byte) bool {
	return c == '.' || c == '_' || c == '$' ||
		'0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

// forEachPropRun calls fn for each maximal run js[start:end] of property path
// characters that contains a '.'.
//
// Every property path match lies within such a run, so the regexes need only
// be run on these (short) runs rather than stepping their NFAs over the whole
// script. The characters around a run are non-word characters, so \b behaves
// the same at the edges of a run as it does in the full script.
func forEachPropRun(js string, fn func(start, end int)) {
	for i := 0; i < len(js); {
		if !isPropPathChar(js[i]) {
			i++
			continue
		}
		start, dot := i, false
		for ; i < len(js) && isPropPathChar(js[i]); i++ {
			dot = dot || js[i] == '.'
		}
		if dot {
			fn(start, i)
		}
	}
}

// propPathMatches returns the same as propPathPattern.FindAllStringSubmatch(js, -1).
func propPathMatches(js string) [][]string {
	skipSpace := func(i int) int {
		for i < len(js) && strings.IndexByte("\t\n\f\r ", js[i]) >= 0 {
			i++
		}
		return i
	}
	var matches [][]string
	forEachPropRun(js, func(start, end int) {
		// A match is a path ending the run, followed by \s*=\s*. The
		// value part of the pattern never consumes more than two quotes
		// (its .*? is lazy and nothing follows it).
		eq := skipSpace(end)
		if eq == len(js) || js[eq] != '=' {
			return
		}
		window := js[start:min(len(js), skipSpace(eq+1)+2)]
		if m := propPathPattern.FindStringSubmatch(window); m != nil {
			matches = append(matches, m)
		}
	})
	return matches
}

// propAccesses returns the same as propAccessPattern.FindAllString(js, -1).
func propAccesses(js string) []string {
	var paths []string
	forEachPropRun(js, func(start, end int) {
		// Most runs are plain paths like "e.exports", which match as a
		// whole: they start and end with a word character (so at a \b) and
		// have no empty segments. '$' isn't a word character, so runs
		// containing it are left to the regex.
		run := js[start:end]
		if run[0] != '.' && run[len(run)-1] != '.' && !strings.Contains(run, "..") && !strings.Contains(run, "$") {
			paths = append(paths, run)
			return
		}
		paths = append(paths, propAccessPattern.FindAllString(run, -1)...)
	})
	return paths
}

// ExtractJSGlobals extracts global JavaScript variables and their values
func ExtractJSGlobals(jsContent string) JSExtractionResult {
	return extractJSGlobals(jsContent, nil)
}

// extractJSGlobals is ExtractJSGlobals, except that if keepAccess is non-nil,
// property accesses (as opposed to assignments) are only recorded if
// keepAccess reports true for their path. Minified bundles contain tens of
// thousands of distinct accesses like "e.exports", so recording only those
// the caller can use saves a lot of memory.
func extractJSGlobals(jsContent string, keepAccess func(path string) bool) JSExtractionResult {
	result := JSExtractionResult{
		HighConfidence:    make(JSGlobals),
		LowConfidence:     make(JSGlobals),
		PropertyPaths:     make(JSGlobals),
		Classes:           []string{},
		DetectedLibraries: make(map[string]string),
	}

	// First, check for known libraries. Find the literals the patterns
	// require in one pass so most regexes can be skipped.
	has := func(lit string) bool { return strings.Contains(jsContent, lit) }
	if len(jsContent) >= minScanLen {
		has = libraryLiterals.scan(jsContent)
	}
	for libraryName, pattern := range libraryPatterns {
		if !pattern.literals.satisfied(has) {
			continue
		}
		if matches := pattern.find(jsContent); len(matches) > 0 {
			version := ""
			if len(matches) > 1 && matches[1] != "" {
				version = matches[1]
			}
			result.DetectedLibraries[libraryName] = version
		}
	}

	// Look for property paths like angular.version.full in assignments
	for _, matches := range propPathMatches(jsContent) {
		if len(matches) >= 3 {
			propPath := matches[1]

			// Determine the value - could be in group 2 or 3 depending on if it was quoted
			value := ""
			if matches[2] != "" {
				value = matches[2]
			} else if len(matches) > 3 && matches[3] != "" {
				value = matches[3]
			}

			// Store the property path
			result.PropertyPaths[propPath] = value

			// Extract the root object and all partial paths to match against JS patterns
			if dot := strings.IndexByte(propPath, '.'); dot >= 0 {
				// Store the root object
				root := propPath[:dot]
				result.HighConfidence[root] = propPath

				// Store partial paths (e.g., "angular.version" from "angular.version.full")
				for i := dot + 1; i <= len(propPath); i++ {
					if i < len(propPath) && propPath[i] != '.' {
						continue
					}
					result.HighConfidence[propPath[:i]] = value
				}

				// If this looks like a version property, extract it
				if strings.Contains(propPath, ".version") {
					// Try to extract version using more specific patterns
					if version := versionSemverPattern.FindStringSubmatch(value); len(version) > 1 {
						result.DetectedLibraries[root] = version[1]
					} else if version := versionPattern.FindString(value); version != "" {
						result.DetectedLibraries[root] = version
					}
				}
			}
		}
	}

	// Also find property accesses (not just assignments) for more comprehensive detection.
	// The \b anchors are zero-width, so the whole match is the property path.
	for _, propPath := range propAccesses(jsContent) {
		if keepAccess == nil || keepAccess(propPath) {
			// Don't overwrite existing property paths from assignments
			if _, exists := result.PropertyPaths[propPath]; !exists {
				result.PropertyPaths[propPath] = ""

				// Extract the root object and all partial paths
				if dot := strings.IndexByte(propPath, '.'); dot >= 0 {
					// Store the root object if not already stored
					root := propPath[:dot]
					if _, exists := result.HighConfidence[root]; !exists {
						result.HighConfidence[root] = propPath
					}

					// Store intermediate paths for better matching
					for i := dot + 1; i <= len(propPath); i++ {
						if i < len(propPath) && propPath[i] != '.' {
							continue
						}
						if _, exists := result.HighConfidence[propPath[:i]]; !exists {
							result.HighConfidence[propPath[:i]] = ""
						}
					}
				}
			}
		}
	}

	// Split JS content into statements for more detailed analysis
	statements := SplitIntoStatements(jsContent)

	// Extract variables from each statement
	for _, statement := range statements {
		statement = strings.TrimSpace(statement)

		// Extract direct variable declarations
		if matches := varDeclPattern.FindStringSubmatch(statement); len(matches) >= 3 {
			varName := matches[1]
			varValue := strings.TrimSpace(matches[2])

			// Skip very short variable names (likely to be generic)
			if len(varName) < 3 {
				result.LowConfidence[varName] = varValue
			} else {
				result.HighConfidence[varName] = varValue
			}
			continue
		}

		// Extract window assignments
		if matches := windowAssignPattern.FindStringSubmatch(statement); len(matches) >= 3 {
			varName := matches[1]
			varValue := strings.TrimSpace(matches[2])
			result.HighConfidence[varName] = varValue
			continue
		}

		// Extract this assignments
		if matches := thisAssignPattern.FindStringSubmatch(statement); len(matches) >= 3 {
			varName := matches[1]
			varValue := strings.TrimSpace(matches[2])

			// this.x = y is not always a global, use lower confidence
			result.LowConfidence[varName] = varValue
			continue
		}

		// Extract global assignments
		if matches := globalAssignPattern.FindStringSubmatch(statement); len(matches) >= 3 {
			varName := matches[1]
			varValue := strings.TrimSpace(matches[2])

			// direct assignment without var could be anything, use lower confidence
			result.LowConfidence[varName] = varValue
			continue
		}

		// Extract class additions
		for _, matches := range classAddPattern.FindAllStringSubmatch(statement, -1) {
			if len(matches) >= 2 {
				className := matches[1]
				result.Classes = append(result.Classes, className)
			}
		}
	}

	return result
}

