package main

import (
	"strings"
)

// Merging the sources.
//
// The sources are ranked (see sourceSpecs). A tech in several sources gets:
//
//   - the union of the patterns of each list field (html, scriptSrc,
//     implies, ...);
//   - for meta and dns, the union of the patterns of each key, where a key
//     that just has to exist in one source just has to exist in the merge;
//   - for cookies, headers and js, which have one pattern per key: the
//     pattern if they agree; "" if either is "" (existence absorbs any
//     pattern); (?:a)|(?:b) if neither has \; modifiers; else the pattern of
//     the higher-ranked source;
//   - for dom, the union of the selectors; the checks of a selector in
//     several sources are merged check by check (and attribute by
//     attribute), keeping the higher-ranked one on conflict;
//   - each scalar (cats, description, website, icon, cpe, probe) and gate
//     (requires, requiresCategory, excludes) from the highest-ranked source
//     that has it.

// mergeTech merges src, from a lower-ranked source, into dst.
func mergeTech(dst, src *Tech, stats counter) {
	if len(dst.Cats) == 0 {
		dst.Cats = src.Cats
	}
	if dst.Description == "" {
		dst.Description = src.Description
	}
	if dst.Website == "" {
		dst.Website = src.Website
	}
	if dst.Icon == "" {
		dst.Icon = src.Icon
	}
	if dst.CPE == "" {
		dst.CPE = src.CPE
	}
	if len(dst.Probe) == 0 {
		dst.Probe = src.Probe
	}
	if len(dst.Requires) == 0 {
		dst.Requires = src.Requires
	}
	if len(dst.RequiresCategory) == 0 {
		dst.RequiresCategory = src.RequiresCategory
	}
	if len(dst.Excludes) == 0 {
		dst.Excludes = src.Excludes
	}

	for _, f := range listFields {
		p := f.get(dst)
		*p = sortedSet(union(*p, *f.get(src)))
	}
	for _, f := range keyedFields {
		p := f.get(dst)
		*p = mergeKeyed(*p, *f.get(src), f.name, stats)
	}
	for _, f := range multiKeyedFields {
		p := f.get(dst)
		*p = mergeMultiKeyed(*p, *f.get(src))
	}
	dst.DOM = mergeDOM(dst.DOM, src.DOM, stats)
}

// listField is a field of a Tech that is a list of patterns or names.
type listField struct {
	name string
	get  func(*Tech) *[]string
	// pattern reports whether the elements are patterns, not tech names.
	pattern bool
}

var listFields = []listField{
	{"css", func(t *Tech) *[]string { return &t.CSS }, true},
	{"html", func(t *Tech) *[]string { return &t.HTML }, true},
	{"text", func(t *Tech) *[]string { return &t.Text }, true},
	{"scripts", func(t *Tech) *[]string { return &t.Scripts }, true},
	{"scriptSrc", func(t *Tech) *[]string { return &t.ScriptSrc }, true},
	{"url", func(t *Tech) *[]string { return &t.URL }, true},
	{"xhr", func(t *Tech) *[]string { return &t.XHR }, true},
	{"robots", func(t *Tech) *[]string { return &t.Robots }, true},
	{"certIssuer", func(t *Tech) *[]string { return &t.CertIssuer }, true},
	{"implies", func(t *Tech) *[]string { return &t.Implies }, false},
}

// gateFields are the list fields naming techs that gate a tech. Unlike
// listFields they aren't unioned when merging.
var gateFields = []listField{
	{"requires", func(t *Tech) *[]string { return &t.Requires }, false},
	{"excludes", func(t *Tech) *[]string { return &t.Excludes }, false},
}

// keyedField is a field of a Tech with one pattern per key.
type keyedField struct {
	name string
	get  func(*Tech) *map[string]string
}

var keyedFields = []keyedField{
	{"cookies", func(t *Tech) *map[string]string { return &t.Cookies }},
	{"headers", func(t *Tech) *map[string]string { return &t.Headers }},
	{"js", func(t *Tech) *map[string]string { return &t.JS }},
}

// multiKeyedField is a field of a Tech with a list of patterns per key.
type multiKeyedField struct {
	name string
	get  func(*Tech) *map[string][]string
}

var multiKeyedFields = []multiKeyedField{
	{"meta", func(t *Tech) *map[string][]string { return &t.Meta }},
	{"dns", func(t *Tech) *map[string][]string { return &t.DNS }},
}

func mergeKeyed(dst, src map[string]string, field string, stats counter) map[string]string {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]string, len(src))
	}
	for _, k := range sortedKeys(src) {
		if cur, ok := dst[k]; ok {
			dst[k] = combinePatterns(cur, src[k], field, stats)
		} else {
			dst[k] = src[k]
		}
	}
	return dst
}

// combinePatterns returns a pattern for a key that has pattern a in a
// source and b in a lower-ranked one.
func combinePatterns(a, b, field string, stats counter) string {
	switch {
	case a == b:
		return a
	case a == "" || b == "":
		stats[field+": existence check absorbed a pattern"]++
		return ""
	case strings.Contains(a, `\;`) || strings.Contains(b, `\;`):
		stats[field+": conflicting patterns with modifiers (kept higher-ranked)"]++
		return a
	case strings.Contains(a, "(?:"+b+")"):
		return a
	}
	stats[field+": conflicting patterns alternated"]++
	return "(?:" + a + ")|(?:" + b + ")"
}

func mergeMultiKeyed(dst, src map[string][]string) map[string][]string {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string][]string, len(src))
	}
	for _, k := range sortedKeys(src) {
		dst[k] = unionKeyed(dst[k], hasKey(dst, k), src[k])
	}
	return dst
}

func mergeDOM(dst, src map[string]*DOMCheck, stats counter) map[string]*DOMCheck {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]*DOMCheck, len(src))
	}
	for _, sel := range sortedKeys(src) {
		if cur, ok := dst[sel]; ok {
			dst[sel] = mergeDOMCheck(cur, src[sel], stats)
		} else {
			dst[sel] = src[sel].clone()
		}
	}
	return dst
}

// mergeDOMCheck merges the checks b of a selector into a, from a
// higher-ranked source, keeping those of a on conflict.
func mergeDOMCheck(a, b *DOMCheck, stats counter) *DOMCheck {
	out := a.clone()
	mergeString := func(dst **string, src *string) {
		switch {
		case src == nil:
		case *dst == nil:
			*dst = src
		case **dst != *src:
			stats["dom: conflicting checks (kept higher-ranked)"]++
		}
	}
	mergeString(&out.Exists, b.Exists)
	mergeString(&out.Text, b.Text)
	for _, name := range sortedKeys(b.Attributes) {
		cur, ok := out.Attributes[name]
		switch {
		case !ok:
			out.setAttribute(name, b.Attributes[name])
		case cur != b.Attributes[name]:
			stats["dom: conflicting attribute checks (kept higher-ranked)"]++
		}
	}
	if len(out.Properties) == 0 && len(b.Properties) > 0 {
		out.Properties = b.Properties
	}
	return out
}

// mergeSources merges the techs of the sources, which are in rank order.
func mergeSources(sources []*source, stats counter) map[string]*Tech {
	merged := make(map[string]*Tech)
	inSources := make(map[string]int)
	for _, src := range sources {
		for _, name := range sortedKeys(src.techs) {
			inSources[name]++
			t := src.techs[name]
			if cur, ok := merged[name]; ok {
				mergeTech(cur, t, stats)
			} else {
				merged[name] = cloneTech(t)
			}
		}
	}
	for _, n := range inSources {
		if n == 1 {
			stats["techs in one source"]++
		} else {
			stats["techs in several sources"]++
		}
	}
	return merged
}

// cloneTech returns a copy of t that shares no maps or check structs with
// it, so merging into it leaves t alone.
func cloneTech(t *Tech) *Tech {
	out := *t
	for _, f := range keyedFields {
		if m := *f.get(t); m != nil {
			c := make(map[string]string, len(m))
			for k, v := range m {
				c[k] = v
			}
			*f.get(&out) = c
		}
	}
	for _, f := range multiKeyedFields {
		if m := *f.get(t); m != nil {
			c := make(map[string][]string, len(m))
			for k, v := range m {
				c[k] = append([]string{}, v...)
			}
			*f.get(&out) = c
		}
	}
	if t.DOM != nil {
		out.DOM = make(map[string]*DOMCheck, len(t.DOM))
		for sel, c := range t.DOM {
			out.DOM[sel] = c.clone()
		}
	}
	return &out
}
