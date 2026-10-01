package profiler

import (
	"regexp"
	"sort"
	"strings"
)

// Compiling fingerprints from their JSON form.
//
// The embedded fingerprints are compiled at build time by kitsune-gen (see
// gen.go), using the same code as NewFromFile uses at run time.

// compiler compiles fingerprints.
type compiler struct {
	// selectors holds the dom selectors compiled so far, so that each is
	// compiled once.
	selectors map[string]*domSelector
	// dropped lists the patterns dropped because their regex didn't compile.
	dropped []string
}

// compileFingerprints compiles apps. It also returns the patterns dropped
// because their regex doesn't compile.
func compileFingerprints(apps map[string]*Fingerprint) (*CompiledFingerprints, []string) {
	c := &compiler{selectors: make(map[string]*domSelector)}
	f := &CompiledFingerprints{Apps: make([]*CompiledFingerprint, 0, len(apps))}
	for _, name := range sortedKeys(apps) {
		f.Apps = append(f.Apps, c.fingerprint(name, apps[name]))
	}
	f.buildIndexes()
	return f, c.dropped
}

// pattern parses a wappalyzer pattern, deriving its prefilter if prefilter
// is set. It returns nil if the pattern's regex doesn't compile.
func (c *compiler) pattern(raw string, prefilter bool) *ParsedPattern {
	p, err := ParsePattern(raw)
	if err != nil {
		c.dropped = append(c.dropped, raw)
		return nil
	}
	if prefilter {
		p.initPrefilter()
	}
	return p
}

func (c *compiler) patterns(raws []string, prefilter bool) []*ParsedPattern {
	out := make([]*ParsedPattern, 0, len(raws))
	for _, raw := range raws {
		if p := c.pattern(raw, prefilter); p != nil {
			out = append(out, p)
		}
	}
	return out
}

// keyed compiles patterns for the values of keys. Keys are lowercased if
// lower is set, as the keys they are matched against are.
func (c *compiler) keyed(raws map[string]string, lower bool) []keyedPattern {
	var out []keyedPattern
	for _, key := range sortedKeys(raws) {
		if p := c.pattern(raws[key], false); p != nil {
			if lower {
				key = strings.ToLower(key)
			}
			out = append(out, keyedPattern{key: key, pattern: p})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

// multiKeyed compiles lists of patterns for the values of keys, which are
// lowercased if lower is set. An empty list means that the key must merely
// be present, so it is compiled as the pattern matching anything. A key
// none of whose patterns compile is dropped.
func (c *compiler) multiKeyed(raws map[string][]string, lower bool) []keyedPatterns {
	var out []keyedPatterns
	for _, key := range sortedKeys(raws) {
		list := raws[key]
		if len(list) == 0 {
			list = []string{""}
		}
		patterns := c.patterns(list, false)
		if len(patterns) == 0 {
			continue
		}
		if lower {
			key = strings.ToLower(key)
		}
		out = append(out, keyedPatterns{key: key, patterns: patterns})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

func (c *compiler) selector(selector string) *domSelector {
	sel, ok := c.selectors[selector]
	if !ok {
		sel = newDOMSelector(selector)
		c.selectors[selector] = sel
	}
	return sel
}

// domRule compiles the checks of a dom selector. Each check ("exists",
// "text" or an attribute) is a detection of its own, as in wappalyzer, so a
// check whose regex doesn't compile is dropped on its own. It reports false
// if the rule has no checks left, or if it inspects "properties", which are
// JS runtime values absent from static HTML: such rules are dropped as a
// whole.
func (c *compiler) domRule(selector string, raws map[string]interface{}) (domRule, bool) {
	checks := make(map[string]*ParsedPattern)
	add := func(name string, value interface{}) {
		if raw, ok := value.(string); ok {
			// Prefiltered: element text (of scripts and styles, say) can
			// be large.
			if p := c.pattern(raw, true); p != nil {
				checks[name] = p
			}
		}
	}
	for _, key := range sortedKeys(raws) {
		value := raws[key]
		switch key {
		case "properties":
			return domRule{}, false
		case "attributes":
			attrs, ok := value.(map[string]interface{})
			if !ok {
				continue
			}
			// An attribute named "text" is the text of the element:
			// wappalyzer's data puts it there in a few places.
			for _, name := range sortedKeys(attrs) {
				add(name, attrs[name])
			}
		default:
			// "exists", "text", or an attribute given directly (like
			// "src" or "class").
			add(key, value)
		}
	}
	if len(checks) == 0 {
		return domRule{}, false
	}
	rule := domRule{sel: c.selector(selector)}
	for _, name := range sortedKeys(checks) {
		rule.checks = append(rule.checks, domCheck{name: name, pattern: checks[name]})
	}
	return rule, true
}

// fingerprint compiles a fingerprint.
func (c *compiler) fingerprint(name string, fingerprint *Fingerprint) *CompiledFingerprint {
	compiled := &CompiledFingerprint{
		name:             name,
		cats:             fingerprint.Cats,
		implies:          fingerprint.Implies,
		requires:         fingerprint.Requires,
		requiresCategory: fingerprint.RequiresCategory,
		excludes:         fingerprint.Excludes,
		info:             newInfo(fingerprint.Description, fingerprint.Website, fingerprint.Icon, fingerprint.CPE),
		cookies:          c.keyed(fingerprint.Cookies, true),
		js:               c.keyed(fingerprint.JS, false),
		headers:          c.keyed(fingerprint.Headers, true),
		html:             c.patterns(fingerprint.HTML, true),
		script:           c.patterns(fingerprint.Script, true),
		scriptSrc:        c.patterns(fingerprint.ScriptSrc, true),
		meta:             c.multiKeyed(fingerprint.Meta, true),
		dns:              c.multiKeyed(fingerprint.DNS, false),
		certIssuer:       c.patterns(fingerprint.CertIssuer, true),
		css:              c.patterns(fingerprint.CSS, true),
		text:             c.patterns(fingerprint.Text, true),
		url:              c.patterns(fingerprint.URL, true),
	}
	for _, selector := range sortedKeys(fingerprint.Dom) {
		if rule, ok := c.domRule(selector, fingerprint.Dom[selector]); ok {
			compiled.dom = append(compiled.dom, rule)
		}
	}
	return compiled
}

// buildIndexes sorts Apps. It must be called once all fingerprints have
// been added.
func (f *CompiledFingerprints) buildIndexes() {
	sort.SliceStable(f.Apps, func(i, j int) bool { return f.Apps[i].name < f.Apps[j].name })
}

// literalLists are the literal lists the lookup structures are built from:
// the prefilter literals of the patterns of the parts matched against large
// inputs, the literals of the dom selectors, and the JS global names used by
// js patterns, sorted.
type literalLists struct {
	html, script, css, text, dom []string
}

// literalLists returns f's literal lists, deriving them on first use.
func (f *CompiledFingerprints) literalLists() *literalLists {
	f.listsOnce.Do(func() {
		var html, script, css, text, dom literalList
		seenSelectors := make(map[*domSelector]bool)
		for _, fp := range f.Apps {
			html.addPatterns(fp.html)
			script.addPatterns(fp.script)
			css.addPatterns(fp.css)
			text.addPatterns(fp.text)
			for _, rule := range fp.dom {
				if seenSelectors[rule.sel] {
					continue
				}
				seenSelectors[rule.sel] = true
				for _, part := range rule.sel.literals {
					dom.add(part...)
				}
			}
		}
		f.lists = literalLists{html: html.list, script: script.list, css: css.list, text: text.list, dom: dom.list}
	})
	return &f.lists
}

// literalList is a list of distinct non-empty strings.
type literalList struct {
	list []string
	seen map[string]bool
}

func (l *literalList) add(lits ...string) {
	if l.seen == nil {
		l.seen = make(map[string]bool)
	}
	for _, lit := range lits {
		if lit != "" && !l.seen[lit] {
			l.seen[lit] = true
			l.list = append(l.list, lit)
		}
	}
}

func (l *literalList) addPatterns(patterns []*ParsedPattern) {
	for _, pattern := range patterns {
		for _, set := range pattern.literals {
			l.add(set...)
		}
	}
}

// withBoundedRepeats returns a copy of f whose regexes are rewritten with
// the {1,250}/{0,250} repeat bounds, compiling them and dropping the
// patterns whose regex no longer compiles, exactly as if f had been
// compiled with unboundedRepeats unset. The patterns of f must have been
// compiled with unboundedRepeats set.
func (f *CompiledFingerprints) withBoundedRepeats() *CompiledFingerprints {
	bounded := &CompiledFingerprints{Apps: make([]*CompiledFingerprint, 0, len(f.Apps))}
	for _, fp := range f.Apps {
		bounded.Apps = append(bounded.Apps, fp.mapPatterns(boundPattern))
	}
	bounded.buildIndexes()
	return bounded
}

// boundPattern returns p with the repeat bounds applied to its regex, or nil
// if the resulting regex doesn't compile.
func boundPattern(p *ParsedPattern, prefilter bool) *ParsedPattern {
	q := &ParsedPattern{Confidence: p.Confidence, Version: p.Version, SkipRegex: p.SkipRegex}
	if p.src == "" {
		return q
	}
	// See rewriteRegex for why applying it again is equivalent.
	q.src = "(?i)" + rewriteRegex(strings.TrimPrefix(p.src, "(?i)"), true)
	re, err := regexp.Compile(q.src)
	if err != nil {
		return nil
	}
	q.regex = re
	if prefilter {
		q.initPrefilter()
	}
	return q
}

// mapPatterns returns a copy of fp with every pattern p replaced by
// conv(p, prefilter), where prefilter reports whether p's part uses
// prefilters. Patterns for which conv returns nil are dropped, as
// compileFingerprint drops those whose regex doesn't compile.
func (fp *CompiledFingerprint) mapPatterns(conv func(p *ParsedPattern, prefilter bool) *ParsedPattern) *CompiledFingerprint {
	list := func(ps []*ParsedPattern, prefilter bool) []*ParsedPattern {
		out := make([]*ParsedPattern, 0, len(ps))
		for _, p := range ps {
			if q := conv(p, prefilter); q != nil {
				out = append(out, q)
			}
		}
		return out
	}
	keyed := func(kps []keyedPattern) []keyedPattern {
		var out []keyedPattern
		for _, kp := range kps {
			if q := conv(kp.pattern, false); q != nil {
				out = append(out, keyedPattern{key: kp.key, pattern: q})
			}
		}
		return out
	}
	multiKeyed := func(kps []keyedPatterns) []keyedPatterns {
		var out []keyedPatterns
		for _, kp := range kps {
			if patterns := list(kp.patterns, false); len(patterns) > 0 {
				out = append(out, keyedPatterns{key: kp.key, patterns: patterns})
			}
		}
		return out
	}
	out := *fp
	out.cookies = keyed(fp.cookies)
	out.js = keyed(fp.js)
	out.headers = keyed(fp.headers)
	out.html = list(fp.html, true)
	out.script = list(fp.script, true)
	out.scriptSrc = list(fp.scriptSrc, true)
	out.meta = multiKeyed(fp.meta)
	out.dns = multiKeyed(fp.dns)
	out.certIssuer = list(fp.certIssuer, true)
	out.css = list(fp.css, true)
	out.text = list(fp.text, true)
	out.url = list(fp.url, true)
	out.dom = nil
	// As in compiler.domRule, a dom check is dropped on its own if conv
	// drops it, and the rule if it has no checks left.
	for _, rule := range fp.dom {
		mapped := domRule{sel: rule.sel}
		for _, check := range rule.checks {
			if q := conv(check.pattern, true); q != nil {
				mapped.checks = append(mapped.checks, domCheck{name: check.name, pattern: q})
			}
		}
		if len(mapped.checks) > 0 {
			out.dom = append(out.dom, mapped)
		}
	}
	return &out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
