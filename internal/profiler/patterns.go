package profiler

import (
	"os"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ParsedPattern encapsulates a regular expression with
// additional metadata for confidence and version extraction.
type ParsedPattern struct {
	regex *regexp.Regexp
	// literals are lowercase literals required by regex: it can only match
	// a target if strings.ToLower(target) contains them. See prefilter.go.
	literals literalSets

	Confidence int
	Version    string
	SkipRegex  bool
}

const (
	verCap1        = `(\d+(?:\.\d+)+)` // captures 1 set of digits '\d+' followed by one or more '\.\d+' patterns
	verCap1Fill    = "__verCap1__"
	verCap1Limited = `(\d{1,20}(?:\.\d{1,20}){1,20})`

	verCap2        = `((?:\d+\.)+\d+)` // captures 1 or more '\d+\.' patterns followed by 1 set of digits '\d+'
	verCap2Fill    = "__verCap2__"
	verCap2Limited = `((?:\d{1,20}\.){1,20}\d{1,20})`
)

// unboundedRepeats disables the {1,250}/{0,250} rewrite. Go's RE2 engine is
// linear-time, so the rewrite buys no ReDoS protection but multiplies the size
// of compiled programs (~50MB of heap across all fingerprints).
var unboundedRepeats = os.Getenv("KITSUNE_BOUNDED_REPEATS") == ""

// ParsePattern extracts information from a pattern, supporting both regex and simple patterns
func ParsePattern(pattern string) (*ParsedPattern, error) {
	parts := strings.Split(pattern, "\\;")
	p := &ParsedPattern{Confidence: 100}

	if parts[0] == "" {
		p.SkipRegex = true
	}
	for i, part := range parts {
		if i == 0 {
			if p.SkipRegex {
				continue
			}
			regexPattern := part

			// save version capture groups
			regexPattern = strings.ReplaceAll(regexPattern, verCap1, verCap1Fill)
			regexPattern = strings.ReplaceAll(regexPattern, verCap2, verCap2Fill)

			regexPattern = strings.ReplaceAll(regexPattern, "\\+", "__escapedPlus__")
			if !unboundedRepeats {
				regexPattern = strings.ReplaceAll(regexPattern, "+", "{1,250}")
				regexPattern = strings.ReplaceAll(regexPattern, "*", "{0,250}")
			}
			regexPattern = strings.ReplaceAll(regexPattern, "__escapedPlus__", "\\+")

			// restore version capture groups
			regexPattern = strings.ReplaceAll(regexPattern, verCap1Fill, verCap1Limited)
			regexPattern = strings.ReplaceAll(regexPattern, verCap2Fill, verCap2Limited)

			var err error
			p.regex, err = regexp.Compile("(?i)" + regexPattern)
			if err != nil {
				return nil, err
			}
		} else {
			keyValue := strings.SplitN(part, ":", 2)
			if len(keyValue) < 2 {
				continue
			}

			switch keyValue[0] {
			case "confidence":
				conf, err := strconv.Atoi(keyValue[1])
				if err != nil {
					// If conversion fails, keep default confidence
					p.Confidence = 100
				} else {
					p.Confidence = conf
				}
			case "version":
				p.Version = keyValue[1]
			}
		}
	}
	return p, nil
}

// initPrefilter derives the literal prefilter for p. It is only worth doing
// for patterns that are evaluated against large inputs.
func (p *ParsedPattern) initPrefilter() {
	if p.regex != nil {
		p.literals = requiredLiterals(p.regex.String(), true)
	}
}

// mayMatch reports whether p could match a target, given has reporting
// whether a literal occurs in the lowercased target. A false result means
// Evaluate would certainly fail. Callers must not use the prefilter if the
// lowercased target contains foldHazard.
func (p *ParsedPattern) mayMatch(has func(lit string) bool) bool {
	return p.literals.satisfied(has)
}

func (p *ParsedPattern) Evaluate(target string, timeout time.Duration) (bool, string) {
	if p.SkipRegex {
		return true, ""
	}
	if p.regex == nil {
		return false, ""
	}

	var submatches []string
	if unboundedRepeats {
		// RE2 is linear-time; matching directly avoids a goroutine, a timer and
		// two copies of target per pattern.
		submatches = p.regex.FindStringSubmatch(target)
	} else {
		submatches = matchWithTimeout(p.regex, []byte(target), timeout)
	}
	if len(submatches) == 0 {
		return false, ""
	}
	extractedVersion, _ := p.extractVersion(submatches)
	return true, extractedVersion
}

// extractVersion uses the provided pattern to extract version information from a target string.
func (p *ParsedPattern) extractVersion(submatches []string) (string, error) {
	if len(submatches) == 0 {
		return "", nil // No matches found
	}

	result := p.Version
	for i, match := range submatches[1:] { // Start from 1 to skip the entire match
		placeholder := fmt.Sprintf("\\%d", i+1)
		result = strings.ReplaceAll(result, placeholder, match)
	}

	// Evaluate any ternary expressions in the result
	result, err := evaluateVersionExpression(result, submatches[1:])
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(result), nil
}

// evaluateVersionExpression handles ternary expressions in version strings.
func evaluateVersionExpression(expression string, submatches []string) (string, error) {
	if strings.Contains(expression, "?") {
		parts := strings.Split(expression, "?")
		if len(parts) != 2 {
			return "", fmt.Errorf("invalid ternary expression: %s", expression)
		}

		trueFalseParts := strings.Split(parts[1], ":")
		if len(trueFalseParts) != 2 {
			return "", fmt.Errorf("invalid true/false parts in ternary expression: %s", expression)
		}

		if trueFalseParts[0] != "" { // Simple existence check
			if len(submatches) == 0 {
				return trueFalseParts[1], nil
			}
			return trueFalseParts[0], nil
		}
		if trueFalseParts[1] == "" {
			if len(submatches) == 0 {
				return "", nil
			}
			return trueFalseParts[0], nil
		}
		return trueFalseParts[1], nil
	}

	return expression, nil
}
