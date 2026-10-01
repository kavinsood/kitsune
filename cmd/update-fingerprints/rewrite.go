package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Rewriting patterns written for JavaScript's regex engine into RE2, Go's.
//
// The engine compiles the regex part of a pattern (before any \; modifiers)
// case-insensitively, as (?i)regex (see ParsePattern in
// internal/profiler/patterns.go); a pattern whose regex doesn't compile is
// dropped. Most source patterns are valid RE2, and those are left alone.
// The others are rewritten, in order, until they compile:
//
//  1. JavaScript syntax RE2 lacks but which means the same:
//     - identity escapes: \ before a letter that isn't an escape is the
//     letter (\l is l);
//     - \uhhhh is \x{hhhh};
//     - a - next to a class escape in a character class, as in [\d\.-\w],
//     is a literal -;
//     - repeat counts above RE2's limit of 1000 are lowered to it.
//  2. Lookarounds, which RE2 doesn't have: (?=x) and (?<=x) become (?:x),
//     which matches where the original does (but consumes x); (?!x) and
//     (?<!x) are removed, which loosens the pattern.
//
// Patterns that still don't compile (backreferences, for instance) are
// dropped.

// compileRegex compiles the regex part of a pattern as the engine does.
func compileRegex(re string) (*regexp.Regexp, error) {
	return regexp.Compile("(?i)" + re)
}

// rewriteResult is the outcome of fixRegex.
type rewriteResult struct {
	regex string
	// changes describes the rewrites applied, if any.
	changes []string
	// err is the error compiling the regex if it couldn't be fixed.
	err error
}

// fixRegex returns re rewritten so that it compiles, if need be.
func fixRegex(re string) rewriteResult {
	_, err := compileRegex(re)
	if err == nil {
		return rewriteResult{regex: re}
	}
	res := rewriteResult{regex: re, err: err}
	for _, step := range []func(string) (string, []string){rewriteJSSyntax, rewriteLookarounds} {
		fixed, changes := step(res.regex)
		if len(changes) == 0 {
			continue
		}
		res.regex = fixed
		res.changes = append(res.changes, changes...)
		if _, res.err = compileRegex(fixed); res.err == nil {
			return res
		}
	}
	return res
}

// re2Escapes are the letters RE2 accepts after a backslash.
const re2Escapes = "abfnrtvxdDsSwWBApPQEz"

// classEscapes are the letters of the escapes that stand for a set of
// characters.
const classEscapes = "dDsSwW"

var repeatCount = regexp.MustCompile(`\{(\d+)(,(\d*))?\}`)

// rewriteJSSyntax rewrites JavaScript regex syntax RE2 lacks into RE2 that
// means the same; see step 1 above.
func rewriteJSSyntax(re string) (string, []string) {
	var b strings.Builder
	changes := make(map[string]bool)
	inClass := false
	// afterClassEscape is set right after a class escape inside a class.
	afterClassEscape := false
	for i := 0; i < len(re); i++ {
		c := re[i]
		wasAfterClassEscape := afterClassEscape
		afterClassEscape = false
		switch {
		case c == '\\' && i+1 < len(re):
			n := re[i+1]
			switch {
			case n == 'u' && i+6 <= len(re) && isHex(re[i+2:i+6]):
				b.WriteString(`\x{` + re[i+2:i+6] + `}`)
				changes[`\uhhhh as \x{hhhh}`] = true
				i += 5
				continue
			case isLetter(n) && !strings.ContainsRune(re2Escapes, rune(n)):
				b.WriteByte(n)
				changes[`identity escape \`+string(n)] = true
				i++
				continue
			case inClass && strings.ContainsRune(classEscapes, rune(n)):
				afterClassEscape = true
			}
			b.WriteByte(c)
			b.WriteByte(n)
			i++
		case inClass && c == '-' && (wasAfterClassEscape && i+1 < len(re) && re[i+1] != ']' ||
			i+2 < len(re) && re[i+1] == '\\' && strings.ContainsRune(classEscapes, rune(re[i+2]))):
			b.WriteString(`\-`)
			changes["literal - next to a class escape in a character class"] = true
		case c == '[' && !inClass:
			inClass = true
			b.WriteByte(c)
			// A ] right after [ or [^ is a literal.
			if i+1 < len(re) && re[i+1] == '^' {
				b.WriteByte('^')
				i++
			}
			if i+1 < len(re) && re[i+1] == ']' {
				b.WriteString(`\]`)
				i++
			}
		case c == ']' && inClass:
			inClass = false
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	out := repeatCount.ReplaceAllStringFunc(b.String(), func(m string) string {
		parts := repeatCount.FindStringSubmatch(m)
		clamp := func(s string) string {
			if n, err := strconv.Atoi(s); err == nil && n > 1000 {
				changes["repeat count lowered to 1000"] = true
				return "1000"
			}
			return s
		}
		if parts[2] == "" {
			return "{" + clamp(parts[1]) + "}"
		}
		return "{" + clamp(parts[1]) + "," + clamp(parts[3]) + "}"
	})
	return out, sortedKeys(changes)
}

// rewriteLookarounds replaces the lookarounds of re; see step 2 above.
func rewriteLookarounds(re string) (string, []string) {
	var changes []string
	for {
		start, kind := findLookaround(re)
		if start < 0 {
			return re, changes
		}
		end := closingParen(re, start)
		if end < 0 {
			return re, changes
		}
		inner := re[start+len(kind) : end]
		switch kind {
		case "(?=", "(?<=":
			re = re[:start] + "(?:" + inner + ")" + re[end+1:]
			changes = append(changes, fmt.Sprintf("lookaround %s...) made a group", kind))
		default:
			re = re[:start] + re[end+1:]
			changes = append(changes, fmt.Sprintf("lookaround %s%s) removed", kind, inner))
		}
	}
}

// findLookaround returns the index of the first lookaround in re that
// isn't escaped or in a character class, and its opening, or -1.
func findLookaround(re string) (int, string) {
	inClass := false
	for i := 0; i < len(re); i++ {
		switch c := re[i]; {
		case c == '\\':
			i++
		case c == '[':
			inClass = true
		case c == ']':
			inClass = false
		case c == '(' && !inClass:
			for _, kind := range []string{"(?=", "(?!", "(?<=", "(?<!"} {
				if strings.HasPrefix(re[i:], kind) {
					return i, kind
				}
			}
		}
	}
	return -1, ""
}

// closingParen returns the index of the parenthesis closing the one at
// start, or -1.
func closingParen(re string, start int) int {
	depth, inClass := 0, false
	for i := start; i < len(re); i++ {
		switch c := re[i]; {
		case c == '\\':
			i++
		case inClass:
			inClass = c != ']'
		case c == '[':
			inClass = true
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func isLetter(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
			return false
		}
	}
	return true
}
