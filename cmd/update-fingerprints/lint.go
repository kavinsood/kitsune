package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/andybalholm/cascadia"
)

// Checking the merged fingerprints.
//
// The checks fix what they can (see rewrite.go) and drop what the engine
// can't use, so that every pattern and selector written compiles. Their
// findings are errors or warnings. Errors that aren't in the baseline file
// fail the run (see main.go): they flag data that is lost or broken.

const (
	sevError = "error"
	sevWarn  = "warning"
)

// issue is a finding of the checks.
type issue struct {
	sev, kind, tech, detail string
}

// key identifies an issue in the baseline.
func (i issue) key() string {
	return i.kind + "\t" + i.tech + "\t" + i.detail
}

type linter struct {
	issues []issue
	seen   map[string]bool
	// counts counts the fixes made.
	counts counter
}

func newLinter() *linter {
	return &linter{seen: make(map[string]bool), counts: make(counter)}
}

// add records an issue, reporting whether it is new: the same issue may be
// found in several sources.
func (l *linter) add(sev, kind, tech, format string, args ...any) bool {
	detail := strings.NewReplacer("\n", " ", "\t", " ").Replace(fmt.Sprintf(format, args...))
	i := issue{sev, kind, tech, detail}
	if l.seen[i.key()] {
		return false
	}
	l.seen[i.key()] = true
	l.issues = append(l.issues, i)
	return true
}

// mapPatterns replaces each pattern of t with what f returns for it, or
// drops it if f returns false. A dom rule with a dropped check is dropped
// as a whole, since without the check it would match more. The where
// argument of f names the field and key of the pattern.
func mapPatterns(t *Tech, f func(where, pattern string) (string, bool)) {
	for _, lf := range listFields {
		if !lf.pattern {
			continue
		}
		p := lf.get(t)
		var out []string
		for _, pat := range *p {
			if pat, ok := f(lf.name, pat); ok {
				out = append(out, pat)
			}
		}
		*p = sortedSet(out)
	}
	for _, kf := range keyedFields {
		m := *kf.get(t)
		for _, k := range sortedKeys(m) {
			if pat, ok := f(kf.name+"["+k+"]", m[k]); ok {
				m[k] = pat
			} else {
				delete(m, k)
			}
		}
	}
	for _, mf := range multiKeyedFields {
		m := *mf.get(t)
		for _, k := range sortedKeys(m) {
			if len(m[k]) == 0 {
				continue
			}
			var out []string
			for _, pat := range m[k] {
				if pat, ok := f(mf.name+"["+k+"]", pat); ok {
					out = append(out, pat)
				}
			}
			if len(out) == 0 {
				// An empty list would mean existence.
				delete(m, k)
			} else {
				m[k] = sortedSet(out)
			}
		}
	}
	for _, k := range sortedKeys(t.Probe) {
		if pat, ok := f("probe["+k+"]", t.Probe[k]); ok {
			t.Probe[k] = pat
		} else {
			delete(t.Probe, k)
		}
	}
	for _, sel := range sortedKeys(t.DOM) {
		c := t.DOM[sel]
		keep := true
		mapCheck := func(name string, p *string) {
			if keep && p != nil {
				var ok bool
				*p, ok = f("dom["+sel+"]."+name, *p)
				keep = keep && ok
			}
		}
		// Copy the pointed-to strings, which may be shared.
		if c.Exists != nil {
			s := *c.Exists
			c.Exists = &s
		}
		if c.Text != nil {
			s := *c.Text
			c.Text = &s
		}
		mapCheck("exists", c.Exists)
		mapCheck("text", c.Text)
		for _, name := range sortedKeys(c.Attributes) {
			v := c.Attributes[name]
			mapCheck("attributes."+name, &v)
			c.Attributes[name] = v
		}
		if !keep {
			delete(t.DOM, sel)
		}
	}
}

// fixPatterns rewrites the patterns of techs that don't compile in Go and
// drops those that still don't.
func (l *linter) fixPatterns(techs map[string]*Tech) {
	for _, name := range sortedKeys(techs) {
		mapPatterns(techs[name], func(where, pattern string) (string, bool) {
			orig := pattern
			pattern, sepFixed := fixModifierSeparator(pattern)
			re := regexPart(pattern)
			res := fixRegex(re)
			if sepFixed {
				res.changes = append([]string{`missing \ before the ; of a modifier`}, res.changes...)
			}
			if res.err != nil {
				if l.add(sevError, "regex-dropped", name, "%s: %q: %v", where, orig, res.err) {
					l.counts["patterns dropped: regex doesn't compile"]++
				}
				return "", false
			}
			if len(res.changes) > 0 {
				fixed := res.regex + modifiers(pattern)
				if l.add(sevWarn, "regex-rewritten", name, "%s: %q -> %q (%s)", where, orig, fixed, strings.Join(res.changes, "; ")) {
					l.counts["patterns rewritten for RE2"]++
					for _, c := range res.changes {
						l.counts["rewrite: "+genericChange(c)]++
					}
				}
				return fixed, true
			}
			return pattern, true
		})
	}
}

// fixModifierSeparator inserts the \ missing before the ; of a version or
// confidence modifier, as in `foo\.js;version:\1`, reporting whether it
// did.
func fixModifierSeparator(pattern string) (string, bool) {
	fixed := false
	for _, mod := range []string{";version:", ";confidence:"} {
		for i := 0; ; {
			j := strings.Index(pattern[i:], mod)
			if j < 0 {
				break
			}
			j += i
			if j == 0 || pattern[j-1] != '\\' {
				pattern = pattern[:j] + `\` + pattern[j:]
				fixed = true
				j++
			}
			i = j + len(mod)
		}
	}
	return pattern, fixed
}

// genericChange strips the specifics from a description of a rewrite, for
// counting.
func genericChange(c string) string {
	switch {
	case strings.HasPrefix(c, `identity escape`):
		return "identity escape"
	case strings.HasSuffix(c, "removed"):
		return "negative lookaround removed"
	case strings.HasSuffix(c, "made a group"):
		return "positive lookaround made a group"
	}
	return c
}

// fixSelectors drops the dom selectors that don't parse.
func (l *linter) fixSelectors(techs map[string]*Tech) {
	for _, name := range sortedKeys(techs) {
		t := techs[name]
		for _, sel := range sortedKeys(t.DOM) {
			if _, err := cascadia.Compile(sel); err != nil {
				delete(t.DOM, sel)
				if l.add(sevError, "selector-dropped", name, "%q: %v", sel, err) {
					l.counts["dom selectors dropped: invalid"]++
				}
			}
		}
	}
}

// genericSelectors match elements on nearly any page.
var genericSelectors = map[string]bool{
	"*": true, "html": true, "head": true, "body": true, "div": true, "span": true, "a": true,
	"p": true, "script": true, "link": true, "meta": true, "img": true, "[class]": true, "[id]": true,
	"[style]": true, "[href]": true, "[src]": true,
}

// check reports problems with techs that need a human: references to
// missing techs or categories, patterns that match anything, and selectors
// that match nearly anything.
func (l *linter) check(techs map[string]*Tech, categories map[string]*Category) {
	for _, name := range sortedKeys(techs) {
		t := techs[name]
		refs := []struct {
			field string
			names []string
		}{{"implies", t.Implies}, {"requires", t.Requires}, {"excludes", t.Excludes}}
		for _, ref := range refs {
			for _, target := range ref.names {
				target = regexPart(target)
				switch {
				case target == name && ref.field == "implies":
					l.add(sevWarn, "self-implies", name, "implies itself")
				case techs[target] == nil:
					l.add(sevError, "missing-tech", name, "%s %q, which doesn't exist", ref.field, target)
				}
			}
		}
		for _, cat := range t.Cats {
			if categories[fmt.Sprint(cat)] == nil {
				l.add(sevError, "missing-category", name, "category %d doesn't exist", cat)
			}
		}
		for _, cat := range t.RequiresCategory {
			if categories[fmt.Sprint(cat)] == nil {
				l.add(sevError, "missing-category", name, "requiresCategory %d doesn't exist", cat)
			}
		}
		if len(t.Cats) == 0 {
			l.add(sevWarn, "no-category", name, "has no categories")
		}

		for _, field := range []string{"html", "text", "scripts", "scriptSrc", "css", "url", "xhr", "robots", "certIssuer"} {
			for _, pattern := range *fieldByName(field).get(t) {
				re := regexPart(pattern)
				if re == "" {
					l.add(sevWarn, "matches-anything", name, "%s: %q is empty, so matches anything", field, pattern)
				} else if r, err := compileRegex(re); err == nil && r.MatchString("") {
					l.add(sevWarn, "matches-anything", name, "%s: %q matches the empty string", field, pattern)
				}
			}
		}
		for _, sel := range sortedKeys(t.DOM) {
			c := t.DOM[sel]
			switch {
			case c.empty():
				l.add(sevWarn, "dom-no-checks", name, "%q has no checks", sel)
			case genericSelectors[strings.TrimSpace(sel)] && (c.isExistsOnly() || c.Text != nil && regexPart(*c.Text) == ""):
				l.add(sevWarn, "dom-generic", name, "%q matches nearly any page", sel)
			}
		}
	}
}

func fieldByName(name string) listField {
	for _, f := range listFields {
		if f.name == name {
			return f
		}
	}
	panic("no list field " + name)
}

// signals returns the number of patterns and selectors t is detected by.
func signals(t *Tech) int {
	n := len(t.DOM) + len(t.Probe)
	for _, f := range listFields {
		if f.pattern {
			n += len(*f.get(t))
		}
	}
	for _, f := range keyedFields {
		n += len(*f.get(t))
	}
	for _, f := range multiKeyedFields {
		n += len(*f.get(t))
	}
	return n
}

// checkSignals reports the techs that had signals in before but have none
// in after.
func (l *linter) checkSignals(before map[string]int, after map[string]*Tech) {
	for _, name := range sortedKeys(after) {
		if before[name] > 0 && signals(after[name]) == 0 {
			l.add(sevError, "no-signals", name, "lost all its patterns (had %d)", before[name])
		}
	}
}

// summary returns the number of issues by severity and kind, sorted.
func (l *linter) summary() []string {
	counts := make(counter)
	for _, i := range l.issues {
		counts[i.sev+" "+i.kind]++
	}
	var lines []string
	for _, k := range sortedKeys(counts) {
		lines = append(lines, fmt.Sprintf("%6d %s", counts[k], k))
	}
	return lines
}

// sortedIssues returns the issues sorted by severity, kind and tech.
func (l *linter) sortedIssues() []issue {
	out := append([]issue(nil), l.issues...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.sev != b.sev {
			return a.sev < b.sev
		}
		if a.kind != b.kind {
			return a.kind < b.kind
		}
		return a.tech < b.tech
	})
	return out
}
