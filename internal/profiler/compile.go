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

func (c *compiler) keyed(raws map[string]string) []keyedPattern {
	var out []keyedPattern
	for _, key := range sortedKeys(raws) {
		if p := c.pattern(raws[key], false); p != nil {
			out = append(out, keyedPattern{key: key, pattern: p})
		}
	}
	return out
}

func (c *compiler) multiKeyed(raws map[string][]string) []keyedPatterns {
	var out []keyedPatterns
	for _, key := range sortedKeys(raws) {
		var patterns []*ParsedPattern
		for _, raw := range raws[key] {
			if p := c.pattern(raw, false); p != nil {
				patterns = append(patterns, p)
			}
		}
		out = append(out, keyedPatterns{key: key, patterns: patterns})
	}
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

// domRule compiles the checks of a dom selector. It reports false if any
// check can't be evaluated (its regex doesn't compile, or it inspects
// "properties", which are JS runtime values absent from static HTML): the
// rule is then dropped as a whole, since dropping just that check would
// loosen the rule (to matching every element the selector finds, if it was
// the only check).
func (c *compiler) domRule(selector string, raws map[string]interface{}) (domRule, bool) {
	checks := make(map[string]*ParsedPattern)
	for _, attr := range sortedKeys(raws) {
		value := raws[attr]
		switch attr {
		case "exists":
			// Just the existence is enough, no need for pattern matching
			checks[attr] = nil
		case "properties":
			return domRule{}, false
		case "attributes":
			// Process attribute patterns
			attrMap, ok := value.(map[string]interface{})
			if !ok {
				return domRule{}, false
			}
			for _, attrName := range sortedKeys(attrMap) {
				patternStr, ok := attrMap[attrName].(string)
				if !ok {
					return domRule{}, false
				}
				p := c.pattern(patternStr, false)
				if p == nil {
					return domRule{}, false
				}
				checks[attrName] = p
			}
		default:
			// "text" (text content matching), or direct attribute
			// matching (like "href", "id", "class")
			patternStr, ok := value.(string)
			if !ok {
				return domRule{}, false
			}
			p := c.pattern(patternStr, false)
			if p == nil {
				return domRule{}, false
			}
			checks[attr] = p
		}
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
		name:       name,
		cats:       fingerprint.Cats,
		implies:    fingerprint.Implies,
		info:       newInfo(fingerprint.Description, fingerprint.Website, fingerprint.Icon, fingerprint.CPE),
		cookies:    c.keyed(fingerprint.Cookies),
		js:         c.keyed(fingerprint.JS),
		headers:    c.keyed(fingerprint.Headers),
		html:       c.patterns(fingerprint.HTML, true),
		script:     c.patterns(fingerprint.Script, false),
		scriptSrc:  c.patterns(fingerprint.ScriptSrc, true),
		meta:       c.multiKeyed(fingerprint.Meta),
		dns:        c.multiKeyed(fingerprint.DNS),
		robots:     c.patterns(fingerprint.Robots, true),
		certIssuer: c.patterns(fingerprint.CertIssuer, true),
		css:        c.patterns(fingerprint.CSS, true),
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
	html, css, robots, dom, jsGlobals []string
}

// literalLists returns f's literal lists, deriving them on first use.
func (f *CompiledFingerprints) literalLists() *literalLists {
	f.listsOnce.Do(func() {
		var html, css, robots, dom, js literalList
		seenSelectors := make(map[*domSelector]bool)
		for _, fp := range f.Apps {
			html.addPatterns(fp.html)
			css.addPatterns(fp.css)
			robots.addPatterns(fp.robots)
			for _, rule := range fp.dom {
				if seenSelectors[rule.sel] {
					continue
				}
				seenSelectors[rule.sel] = true
				for _, part := range rule.sel.literals {
					dom.add(part...)
				}
			}
			for _, kp := range fp.js {
				js.add(kp.key)
			}
		}
		sort.Strings(js.list)
		f.lists = literalLists{html: html.list, css: css.list, robots: robots.list, dom: dom.list, jsGlobals: js.list}
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
			var patterns []*ParsedPattern
			for _, p := range kp.patterns {
				if q := conv(p, false); q != nil {
					patterns = append(patterns, q)
				}
			}
			out = append(out, keyedPatterns{key: kp.key, patterns: patterns})
		}
		return out
	}
	out := *fp
	out.cookies = keyed(fp.cookies)
	out.js = keyed(fp.js)
	out.headers = keyed(fp.headers)
	out.html = list(fp.html, true)
	out.script = list(fp.script, false)
	out.scriptSrc = list(fp.scriptSrc, true)
	out.meta = multiKeyed(fp.meta)
	out.dns = multiKeyed(fp.dns)
	out.robots = list(fp.robots, true)
	out.certIssuer = list(fp.certIssuer, true)
	out.css = list(fp.css, true)
	out.dom = nil
	// A dom rule is dropped as a whole if conv drops any of its checks, as
	// compiler.domRule does.
rules:
	for _, rule := range fp.dom {
		mapped := domRule{sel: rule.sel}
		for _, check := range rule.checks {
			if check.pattern == nil {
				mapped.checks = append(mapped.checks, check)
			} else if q := conv(check.pattern, false); q != nil {
				mapped.checks = append(mapped.checks, domCheck{name: check.name, pattern: q})
			} else {
				continue rules
			}
		}
		out.dom = append(out.dom, mapped)
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
