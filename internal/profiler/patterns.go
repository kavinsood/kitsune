package profiler

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// ParsedPattern encapsulates a regular expression with
// additional metadata for confidence and version extraction.
type ParsedPattern struct {
	// src is the source of the regex, as rewritten by rewriteRegex, or ""
	// if the pattern has no regex. The regex is compiled from it on first
	// use (see re), so patterns that are never evaluated cost nothing.
	src   string
	once  sync.Once
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
			p.src = "(?i)" + rewriteRegex(part, !unboundedRepeats)

			var err error
			p.regex, err = regexp.Compile(p.src)
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
				// Defaulting a bad confidence to 100 would make the
				// pattern more decisive than intended, so reject it.
				conf, err := strconv.Atoi(keyValue[1])
				if err != nil || conf < 0 {
					return nil, fmt.Errorf("invalid confidence in pattern %q", pattern)
				}
				p.Confidence = conf
			case "version":
				p.Version = keyValue[1]
			}
		}
	}
	return p, nil
}

// rewriteRegex rewrites the regex part of a wappalyzer pattern for Go: it
// limits the repetitions in version capture groups and, if bounded, replaces
// the repetition operators + and * with {1,250} and {0,250}.
//
// Applying it with bounded set to the result of applying it with bounded
// unset gives the same as applying it with bounded set to the original, as
// the limited version capture groups contain neither + nor *.
func rewriteRegex(regexPattern string, bounded bool) string {
	// save version capture groups
	regexPattern = strings.ReplaceAll(regexPattern, verCap1, verCap1Fill)
	regexPattern = strings.ReplaceAll(regexPattern, verCap2, verCap2Fill)

	regexPattern = strings.ReplaceAll(regexPattern, "\\+", "__escapedPlus__")
	if bounded {
		regexPattern = strings.ReplaceAll(regexPattern, "+", "{1,250}")
		regexPattern = strings.ReplaceAll(regexPattern, "*", "{0,250}")
	}
	regexPattern = strings.ReplaceAll(regexPattern, "__escapedPlus__", "\\+")

	// restore version capture groups
	regexPattern = strings.ReplaceAll(regexPattern, verCap1Fill, verCap1Limited)
	regexPattern = strings.ReplaceAll(regexPattern, verCap2Fill, verCap2Limited)
	return regexPattern
}

// re returns p's regex, compiling it on first use, or nil if p has none. It
// is safe for concurrent use.
func (p *ParsedPattern) re() *regexp.Regexp {
	p.once.Do(func() {
		if p.regex == nil && p.src != "" {
			// Only patterns whose regex compiles are kept (see
			// compilePattern), so this can't fail with the Go version
			// that generated them. Should it fail anyway, the pattern
			// matches nothing.
			p.regex, _ = regexp.Compile(p.src)
		}
	})
	return p.regex
}

// initPrefilter derives the literal prefilter for p. It is only worth doing
// for patterns that are evaluated against large inputs.
func (p *ParsedPattern) initPrefilter() {
	if p.src != "" {
		p.literals = requiredLiterals(p.src, true)
	}
}

// mayMatch reports whether p could match a target, given has reporting
// whether a literal occurs in prefilterInput(target). A false result means
// Evaluate would certainly fail.
func (p *ParsedPattern) mayMatch(has func(lit string) bool) bool {
	return p.literals.satisfied(has)
}

// Evaluate matches target against p, returning whether it matches and the
// version it yields, which is "" if none or invalid.
func (p *ParsedPattern) Evaluate(target string, timeout time.Duration) (bool, string) {
	if p.SkipRegex {
		// Like wappalyzer's empty regex, which matches with an empty
		// match, so a static version such as "\;version:2" applies.
		return true, p.extractVersion([]string{""})
	}
	re := p.re()
	if re == nil {
		return false, ""
	}

	var submatches []string
	if unboundedRepeats {
		// RE2 is linear-time; matching directly avoids a goroutine, a timer and
		// two copies of target per pattern.
		submatches = re.FindStringSubmatch(target)
	} else {
		submatches = matchWithTimeout(re, []byte(target), timeout)
	}
	if len(submatches) == 0 {
		return false, ""
	}
	return true, p.extractVersion(submatches)
}

// maxVersionMatch is the length of the longest submatch substituted into a
// version, as in wappalyzer.
const maxVersionMatch = 10

// extractVersion returns the version for submatches (the whole match and
// its groups), resolving the backreferences and ternaries in p.Version as
// wappalyzer's resolveVersion does, quirks included: \N is replaced by
// group N, and a ternary \N?a:b, which runs to the end of the version, by
// a if group N is non-empty and b otherwise (substituting into the
// unresolved version, which discards earlier substitutions). Groups longer
// than maxVersionMatch are skipped, leaving their backreferences, the
// first of which is then removed. The result is "" unless it is a valid
// version (see normalizeVersion).
func (p *ParsedPattern) extractVersion(submatches []string) string {
	if p.Version == "" || len(submatches) == 0 {
		return ""
	}
	version := p.Version
	resolved := version
	for i, match := range submatches {
		if utf8.RuneCountInString(match) > maxVersionMatch {
			continue
		}
		ref := `\` + strconv.Itoa(i)
		if start, a, b, ok := ternary(version, ref); ok {
			if match != "" {
				resolved = version[:start] + a
			} else {
				resolved = version[:start] + b
			}
		}
		resolved = strings.ReplaceAll(strings.TrimSpace(resolved), ref, match)
	}
	if i := strings.IndexByte(resolved, '\\'); i >= 0 && i+1 < len(resolved) && '0' <= resolved[i+1] && resolved[i+1] <= '9' {
		resolved = resolved[:i] + resolved[i+2:]
	}
	return normalizeVersion(resolved)
}

// ternary finds the first ternary for the backreference ref in version, as
// the regex ref\?([^:]+):(.*)$ does, returning where it starts and its
// branches.
func ternary(version, ref string) (start int, a, b string, ok bool) {
	for i := 0; i < len(version); {
		j := strings.Index(version[i:], ref+"?")
		if j < 0 {
			break
		}
		start = i + j
		rest := version[start+len(ref)+1:]
		if colon := strings.IndexByte(rest, ':'); colon > 0 {
			return start, rest[:colon], rest[colon+1:], true
		}
		i = start + 1
	}
	return 0, "", "", false
}
