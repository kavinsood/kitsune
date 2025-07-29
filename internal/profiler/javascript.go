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
	varDeclPattern = regexp.MustCompile(`(?:var|let|const)\s+([a-zA-Z0-9_$]+)\s*=\s*([^;]+)`)

	// Window assignments
	windowAssignPattern = regexp.MustCompile(`(?:window|self|top|global)\s*\.\s*([a-zA-Z0-9_$]+)\s*=\s*([^;]+)`)

	// Global this assignments
	thisAssignPattern = regexp.MustCompile(`this\s*\.\s*([a-zA-Z0-9_$]+)\s*=\s*([^;]+)`)

	// Direct global assignments (without var/let/const)
	globalAssignPattern = regexp.MustCompile(`^([a-zA-Z0-9_$]+)\s*=\s*([^;]+)`)

	// Property path assignments (enhanced to capture more formats)
	propPathPattern = regexp.MustCompile(`([a-zA-Z0-9_$]+(?:\.[a-zA-Z0-9_$]+){1,})\s*=\s*(?:['"]?(.*?)['"]?|([0-9][0-9.a-zA-Z_-]+)|true|false|null|undefined)`)

	// Property access patterns (for detection in conditions, function calls, etc.)
	propAccessPattern = regexp.MustCompile(`\b([a-zA-Z0-9_$]+(?:\.[a-zA-Z0-9_$]+){1,})\b`)

	// Object property access for version detection
	versionPropPattern = regexp.MustCompile(`\.version\s*=\s*['"]([0-9.]+)['"]`)

	// Class additions
	classAddPattern = regexp.MustCompile(`(?:classList|className)\s*\.\s*(?:add|toggle)\s*\(\s*['"]([^'"]+)['"]\s*\)`)

	// Version extraction with more flexible patterns
	versionPattern       = regexp.MustCompile(`([0-9]+(?:\.[0-9]+)+)`)
	versionSemverPattern = regexp.MustCompile(`['"](\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9.-]+)?)['"]`)

	// Enhanced library patterns for direct detection
	libraryPatterns = map[string]*regexp.Regexp{
		// jQuery detection patterns
		"jQuery": regexp.MustCompile(`(?:jQuery|\$)(?:\.fn|\.prototype)?\.(?:jquery|version)\s*=\s*['"]([^'"]+)['"]`),

		// Angular framework detection patterns
		"AngularJS": regexp.MustCompile(`(?:angular(?:\.module|\.(version|bootstrap))|ng\.(module|directive))\b`),
		"Angular":   regexp.MustCompile(`(?:ng\.(?:platformBrowserDynamic|core)|@angular)\b`),

		// React framework detection
		"React": regexp.MustCompile(`(?:React(?:\.version\s*=\s*['"]([^'"]+)['"]|\.[a-zA-Z]+\s*=)|react(?:Dom|DOM)(?:\.[a-zA-Z]+)?)`),

		// Vue framework detection
		"Vue": regexp.MustCompile(`(?:Vue(?:\.version\s*=\s*['"]([^'"]+)['"]|\.component|\.[a-zA-Z]+\s*=)|createApp\s*\(|Vue\.createApp\s*\(|VueRouter\b)`),

		// UI frameworks and libraries
		"Modernizr":   regexp.MustCompile(`Modernizr(?:._version\s*=\s*['"]([^'"]+)['"]|\.[a-zA-Z]+\b)`),
		"Bootstrap":   regexp.MustCompile(`(?:bootstrap\.(?:VERSION|Modal)|(?:\.|\s+)(?:modal|carousel|collapse|dropdown|tooltip|popover|tab|alert|button)\()`),
		"Tailwind":    regexp.MustCompile(`tailwind(?:\.config|CSS)`),
		"Material-UI": regexp.MustCompile(`(?:MaterialUI|MUI|material-ui|@mui/material)\b`),

		// JS frameworks and libraries
		"Backbone":   regexp.MustCompile(`Backbone(?:\.VERSION\s*=\s*['"]([^'"]+)['"]|\.(?:Model|View|Router|Collection)\b)`),
		"Ember":      regexp.MustCompile(`Ember(?:\.VERSION\s*=\s*['"]([^'"]+)['"]|\.(?:Application|Component|Object)\b)`),
		"Prototype":  regexp.MustCompile(`Prototype(?:\.Version\s*=\s*['"]([^'"]+)['"]|\.\$)`),
		"MooTools":   regexp.MustCompile(`MooTools(?:\.version\s*=\s*['"]([^'"]+)['"]|\.[a-zA-Z]+\b)`),
		"Dojo":       regexp.MustCompile(`dojo(?:\.version(?:\s*=|\.toString)|\\.(?:declare|require|connect))`),
		"Lodash":     regexp.MustCompile(`_\.(?:VERSION|forEach|map|filter|find|debounce|throttle)\b`),
		"Underscore": regexp.MustCompile(`_\.(?:VERSION|each|map|reduce|filter|find|debounce|throttle)\b`),

		// Payment services and APIs
		"Stripe": regexp.MustCompile(`(?:Stripe\.version\s*=\s*['"]([^'"]+)['"]|Stripe\.(?:setPublishableKey|elements|createToken))`),
		"PayPal": regexp.MustCompile(`(?:paypal\.Buttons|PAYPAL\.apps\.(?:MiniCart|ButtonFactory))`),

		// State management
		"Redux": regexp.MustCompile(`(?:createStore|combineReducers|applyMiddleware|bindActionCreators)\b`),
		"MobX":  regexp.MustCompile(`(?:mobx|observable|computed|action|autorun|reaction)\b`),

		// Analytics and tracking
		"Google Analytics":   regexp.MustCompile(`ga\s*\(\s*['"](?:create|send|set)['"]|GoogleAnalyticsObject|gtag`),
		"Google Tag Manager": regexp.MustCompile(`gtm\.|googletagmanager\.com`),

		// Testing frameworks
		"Jest":  regexp.MustCompile(`(?:jest\.|describe\s*\(\s*['"][^'"]+['"]\s*,\s*\(?function)`),
		"Mocha": regexp.MustCompile(`(?:mocha\.|describe\s*\(\s*['"][^'"]+['"]\s*,\s*\(?function)`),

		// Build tools and bundlers visible in runtime
		"Webpack": regexp.MustCompile(`(?:__webpack_require__|webpackJsonp)`),
		"Babel":   regexp.MustCompile(`babelHelpers`),

		// Utility libraries
		"Moment.js": regexp.MustCompile(`moment(?:\.version|\(|\.\w+\()`),
		"Axios":     regexp.MustCompile(`axios(?:\.(?:get|post|put|delete|patch|request|interceptors))?`),
	}
)

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
	var currentStatement strings.Builder

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
			currentStatement.WriteRune(r)
			escaped = false
			i += width
			continue
		}

		// Check for escape character
		if (inSingleQuote || inDoubleQuote || inTemplate) && r == '\\' {
			currentStatement.WriteRune(r)
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
			currentStatement.WriteRune(r)
			stmt := strings.TrimSpace(currentStatement.String())
			if stmt != "" && stmt != ";" {
				statements = append(statements, stmt)
			}
			currentStatement.Reset()
			i += width
			continue
		}

		// Add character to current statement
		currentStatement.WriteRune(r)

		// Move to the next rune
		i += width
	}

	// Add the last statement if there's content
	lastStatement := strings.TrimSpace(currentStatement.String())
	if lastStatement != "" {
		statements = append(statements, lastStatement)
	}

	return statements
}

// ExtractJSGlobals extracts global JavaScript variables and their values
func ExtractJSGlobals(jsContent string) JSExtractionResult {
	result := JSExtractionResult{
		HighConfidence:    make(JSGlobals),
		LowConfidence:     make(JSGlobals),
		PropertyPaths:     make(JSGlobals),
		Classes:           []string{},
		DetectedLibraries: make(map[string]string),
	}

	// First, check for known libraries
	for libraryName, pattern := range libraryPatterns {
		if matches := pattern.FindStringSubmatch(jsContent); len(matches) > 0 {
			version := ""
			if len(matches) > 1 && matches[1] != "" {
				version = matches[1]
			}
			result.DetectedLibraries[libraryName] = version
		}
	}

	// Look for property paths like angular.version.full in assignments
	for _, matches := range propPathPattern.FindAllStringSubmatch(jsContent, -1) {
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
			parts := strings.Split(propPath, ".")
			if len(parts) >= 2 {
				// Store the root object
				root := parts[0]
				result.HighConfidence[root] = propPath

				// Store partial paths (e.g., "angular.version" from "angular.version.full")
				for i := 1; i < len(parts); i++ {
					partialPath := strings.Join(parts[:i+1], ".")
					result.HighConfidence[partialPath] = value
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

	// Also find property accesses (not just assignments) for more comprehensive detection
	for _, matches := range propAccessPattern.FindAllStringSubmatch(jsContent, -1) {
		if len(matches) >= 2 {
			propPath := matches[1]

			// Don't overwrite existing property paths from assignments
			if _, exists := result.PropertyPaths[propPath]; !exists {
				result.PropertyPaths[propPath] = ""

				// Extract the root object and all partial paths
				parts := strings.Split(propPath, ".")
				if len(parts) >= 2 {
					// Store the root object if not already stored
					root := parts[0]
					if _, exists := result.HighConfidence[root]; !exists {
						result.HighConfidence[root] = propPath
					}

					// Store intermediate paths for better matching
					for i := 1; i < len(parts); i++ {
						partialPath := strings.Join(parts[:i+1], ".")
						if _, exists := result.HighConfidence[partialPath]; !exists {
							result.HighConfidence[partialPath] = ""
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

