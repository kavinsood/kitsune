package profiler

import (
	"strings"
)

// Static evaluation of js patterns.
//
// Wappalyzer's js patterns test the values of JS globals at run time, like
// "jQuery.fn.jquery". A static scanner can't evaluate those, so it only
// looks for explicit assignments of the global a chain starts with:
//
//	window.X = ...    window["X"] = ...    self.X = ...    globalThis.X = ...
//
// and, in classic inline scripts, top-level "var X = ...". Only patterns
// that don't constrain the value are considered (a version capture is
// fine, a required literal isn't), and no version is reported, as the
// assigned value isn't known. A chain below a global other techs use too
// isn't considered. As the chain itself isn't evaluated, a
// match is only evidence: it gets confidence jsConfidence, and all such
// evidence for a tech counts once, unless the global's name is distinctive
// (see distinctiveGlobal).

// jsConfidence is the confidence of an assignment of a global that isn't
// distinctive.
const jsConfidence = 50

// jsTech is a tech with a js pattern whose chain starts at some global.
type jsTech struct {
	app        string
	confidence int
}

// jsGlobals returns the techs with js patterns that can be evaluated
// statically, by the global their chain starts with. Built on first use.
func (f *CompiledFingerprints) jsGlobals() map[string][]jsTech {
	f.jsGlobalsOnce.Do(func() {
		f.jsGlobalTechs = make(map[string][]jsTech)
		// The techs whose chains start at each global. A global several
		// techs hang chains from, like __NEXT_DATA__, is set by one of them
		// (or by something else): its assignment says nothing about the
		// others' properties, so only chains that are the global itself
		// count for it.
		users := make(map[string]map[string]bool)
		for _, fp := range f.Apps {
			for _, kp := range fp.js {
				if root := jsRoot(kp.key); root != "" {
					if users[root] == nil {
						users[root] = make(map[string]bool)
					}
					users[root][fp.name] = true
				}
			}
		}
		for _, fp := range f.Apps {
			seen := make(map[string]bool)
			for _, kp := range fp.js {
				root := jsRoot(kp.key)
				if root == "" || seen[root] || !unconstrained(kp.pattern) {
					continue
				}
				if root != kp.key && len(users[root]) > 1 {
					continue
				}
				seen[root] = true
				confidence := kp.pattern.Confidence
				if !distinctiveGlobal(root) {
					confidence = min(confidence, jsConfidence)
				}
				f.jsGlobalTechs[root] = append(f.jsGlobalTechs[root], jsTech{app: fp.name, confidence: confidence})
			}
		}
	})
	return f.jsGlobalTechs
}

// jsRoot returns the global a js chain starts with, or "" if it isn't an
// identifier.
func jsRoot(chain string) string {
	root, _, _ := strings.Cut(chain, ".")
	if root == "" {
		return ""
	}
	for i := 0; i < len(root); i++ {
		if !isIdentByte(root[i]) {
			return ""
		}
	}
	return root
}

// unconstrained reports whether p accepts any value of a global, as far as
// a static scan can tell: it requires no literal.
func unconstrained(p *ParsedPattern) bool {
	return p.SkipRegex || len(requiredLiterals(p.src, true)) == 0
}

// distinctiveGlobal reports whether the name of a global is distinctive
// enough for its assignment alone to identify a tech: it is long, or
// contains "__" like __NEXT_DATA__.
func distinctiveGlobal(name string) bool {
	return len(name) >= 12 || strings.Contains(name, "__")
}

// matchJSGlobals matches the globals assigned by script against the js
// patterns. topLevel reports whether the top-level var declarations of
// script create globals, as in classic inline scripts.
func (f *CompiledFingerprints) matchJSGlobals(script string, topLevel bool) []matchPartResult {
	techs := f.jsGlobals()
	if len(techs) == 0 {
		return nil
	}
	var technologies []matchPartResult
	seen := make(map[string]bool)
	report := func(name string) {
		if seen[name] {
			return
		}
		seen[name] = true
		for _, t := range techs[name] {
			id := "\x00js"
			if distinctiveGlobal(name) {
				id += " " + name
			}
			technologies = append(technologies, matchPartResult{
				application: t.app,
				confidence:  t.confidence,
				evidence:    evidence{src: id, confidence: t.confidence},
			})
		}
	}
	for _, name := range assignedGlobals(script, topLevel) {
		report(name)
	}
	return technologies
}

// globalObjects are the names through which scripts assign globals.
var globalObjects = []string{"window", "self", "globalThis"}

// assignedGlobals returns the names of the globals script assigns
// explicitly (see the comment at the top of the file), in order, possibly
// with duplicates. Assignments through global objects are found anywhere,
// strings included: telling strings from regexp literals in minified code
// takes a full lexer, and a string assigning a global is usually code that
// runs (inline script HTML, say) anyway.
func assignedGlobals(script string, topLevel bool) []string {
	var names []string
	for _, obj := range globalObjects {
		for i := 0; ; {
			j := strings.Index(script[i:], obj)
			if j < 0 {
				break
			}
			start := i + j
			i = start + len(obj)
			if start > 0 && (isIdentByte(script[start-1]) || script[start-1] == '.') {
				continue
			}
			if name, ok := globalAssignment(script[i:]); ok {
				names = append(names, name)
			}
		}
	}
	if topLevel {
		names = append(names, topLevelVars(script)...)
	}
	return names
}

// globalAssignment parses what follows a global object: a member (.X or
// ["X"]), possibly further members, then an assignment. It returns X.
func globalAssignment(s string) (string, bool) {
	name, rest, ok := member(s)
	if !ok {
		return "", false
	}
	for {
		_, next, ok := member(rest)
		if !ok {
			break
		}
		rest = next
	}
	rest = strings.TrimLeft(rest, " \t\r\n")
	if !strings.HasPrefix(rest, "=") || strings.HasPrefix(rest, "==") || strings.HasPrefix(rest, "=>") {
		return "", false
	}
	return name, true
}

// member parses a member access at the start of s, after optional space:
// .name or ["name"] (or with single quotes).
func member(s string) (name, rest string, ok bool) {
	s = strings.TrimLeft(s, " \t\r\n")
	switch {
	case strings.HasPrefix(s, "."):
		s = strings.TrimLeft(s[1:], " \t\r\n")
		n := identLen(s)
		if n == 0 {
			return "", "", false
		}
		return s[:n], s[n:], true
	case strings.HasPrefix(s, "["):
		s = strings.TrimLeft(s[1:], " \t\r\n")
		if s == "" || s[0] != '"' && s[0] != '\'' {
			return "", "", false
		}
		quote := s[0]
		n := identLen(s[1:])
		if n == 0 || len(s) < n+2 || s[n+1] != quote {
			return "", "", false
		}
		rest = strings.TrimLeft(s[n+2:], " \t\r\n")
		if !strings.HasPrefix(rest, "]") {
			return "", "", false
		}
		return s[1 : n+1], rest[1:], true
	}
	return "", "", false
}

// topLevelVars returns the names declared by "var X =" at the top level of
// script, outside braces, strings and comments.
func topLevelVars(script string) []string {
	var names []string
	depth := 0
	for i := 0; i < len(script); i++ {
		switch c := script[i]; c {
		case '{':
			depth++
		case '}':
			if depth > 0 {
				depth--
			}
		case '"', '\'', '`':
			// Skip the string. Template literals may nest, but braces in
			// them are rare enough not to matter.
			for i++; i < len(script) && script[i] != c; i++ {
				if script[i] == '\\' {
					i++
				}
			}
		case '/':
			if i+1 < len(script) && script[i+1] == '/' {
				for i < len(script) && script[i] != '\n' {
					i++
				}
			} else if i+1 < len(script) && script[i+1] == '*' {
				end := strings.Index(script[i+2:], "*/")
				if end < 0 {
					return names
				}
				i += end + 3
			}
		case 'v':
			if depth > 0 || !strings.HasPrefix(script[i:], "var") || i > 0 && (isIdentByte(script[i-1]) || script[i-1] == '.') {
				continue
			}
			rest := script[i+3:]
			trimmed := strings.TrimLeft(rest, " \t\r\n")
			if len(trimmed) == len(rest) {
				continue // "var" is part of a longer identifier
			}
			n := identLen(trimmed)
			if n == 0 {
				continue
			}
			after := strings.TrimLeft(trimmed[n:], " \t\r\n")
			if strings.HasPrefix(after, "=") && !strings.HasPrefix(after, "==") {
				names = append(names, trimmed[:n])
			}
		}
	}
	return names
}

// identLen returns the length of the identifier at the start of s.
func identLen(s string) int {
	n := 0
	for n < len(s) && isIdentByte(s[n]) {
		n++
	}
	if n > 0 && '0' <= s[0] && s[0] <= '9' {
		return 0
	}
	return n
}

func isIdentByte(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '_' || c == '$'
}
