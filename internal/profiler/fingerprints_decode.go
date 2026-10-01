package profiler

import (
	"fmt"
)

// fingerprintCounts are the numbers of items of each kind in encoded
// fingerprints, so that the decoder can allocate them all at once.
type fingerprintCounts struct {
	patterns, selectors, apps                   int
	literalSets, literals                       int
	cats, names, keyed, patternRefs, multiKeyed int
	domRules, domChecks                         int
}

// fields returns pointers to the counts in encoding order.
func (c *fingerprintCounts) fields() []*int {
	return []*int{&c.patterns, &c.selectors, &c.apps, &c.literalSets, &c.literals,
		&c.cats, &c.names, &c.keyed, &c.patternRefs, &c.multiKeyed, &c.domRules, &c.domChecks}
}

// decodeFingerprints decodes fingerprints encoded by encodeFingerprints. See
// gen.go for the encoding. Everything is allocated in a few large slices,
// and strings are substrings of text.
func decodeFingerprints(data, text string) (f *CompiledFingerprints, err error) {
	d := &decoder{data: data, text: text}
	defer func() {
		if r := recover(); r != nil {
			if de, ok := r.(decodeError); ok {
				f, err = nil, de
				return
			}
			panic(r)
		}
	}()
	f = &CompiledFingerprints{}
	if data == "" {
		return f, nil
	}

	var c fingerprintCounts
	for _, n := range c.fields() {
		*n = d.uint()
	}
	a := &decodeAlloc{
		literalSets: make([][]string, c.literalSets),
		literals:    make([]string, c.literals),
		cats:        make([]int, c.cats),
		names:       make([]string, c.names),
		keyed:       make([]keyedPattern, c.keyed),
		patternRefs: make([]*ParsedPattern, c.patternRefs),
		multiKeyed:  make([]keyedPatterns, c.multiKeyed),
		domRules:    make([]domRule, c.domRules),
		domChecks:   make([]domCheck, c.domChecks),
	}

	patterns := make([]ParsedPattern, c.patterns)
	for i := range patterns {
		p := &patterns[i]
		flags := d.uint()
		if flags&patternHasSrc != 0 {
			p.src = d.str()
		}
		p.Confidence = d.uint()
		if flags&patternHasVersion != 0 {
			p.Version = d.str()
		}
		if flags&patternHasLiterals != 0 {
			p.literals = d.literalSets(a, d.uint())
		}
		p.SkipRegex = flags&patternSkipRegex != 0
	}
	pattern := func() *ParsedPattern {
		i := d.uint()
		if i >= len(patterns) {
			d.fail("pattern index out of range")
		}
		return &patterns[i]
	}

	selectors := make([]domSelector, c.selectors)
	for i := range selectors {
		sel := &selectors[i]
		sel.selector = d.str()
		if n := d.uint(); n > 0 {
			sel.literals = d.literalSets(a, n-1)
		}
	}

	apps := make([]CompiledFingerprint, c.apps)
	f.Apps = make([]*CompiledFingerprint, c.apps)
	for i := range apps {
		fp := &apps[i]
		f.Apps[i] = fp
		fp.name = d.str()
		if n := d.uint(); n > 0 {
			fp.cats = takeNonNil(&a.cats, n-1, d)
			for j := range fp.cats {
				fp.cats[j] = d.uint()
			}
		}
		if n := d.uint(); n > 0 {
			fp.implies = takeNonNil(&a.names, n-1, d)
			for j := range fp.implies {
				fp.implies[j] = d.str()
			}
		}
		fp.requires = take(&a.names, d.uint(), d)
		for j := range fp.requires {
			fp.requires[j] = d.str()
		}
		fp.requiresCategory = take(&a.cats, d.uint(), d)
		for j := range fp.requiresCategory {
			fp.requiresCategory[j] = d.uint()
		}
		fp.excludes = take(&a.names, d.uint(), d)
		for j := range fp.excludes {
			fp.excludes[j] = d.str()
		}
		fp.info = d.str()
		keyed := func() []keyedPattern {
			kps := take(&a.keyed, d.uint(), d)
			for j := range kps {
				kps[j] = keyedPattern{key: d.str(), pattern: pattern()}
			}
			return kps
		}
		list := func() []*ParsedPattern {
			ps := take(&a.patternRefs, d.uint(), d)
			for j := range ps {
				ps[j] = pattern()
			}
			return ps
		}
		multiKeyed := func() []keyedPatterns {
			kps := take(&a.multiKeyed, d.uint(), d)
			for j := range kps {
				kps[j].key = d.str()
				kps[j].patterns = list()
			}
			return kps
		}
		fp.cookies = keyed()
		fp.js = keyed()
		fp.headers = keyed()
		fp.html = list()
		fp.script = list()
		fp.scriptSrc = list()
		fp.meta = multiKeyed()
		fp.dns = multiKeyed()
		fp.certIssuer = list()
		fp.css = list()
		fp.text = list()
		fp.url = list()
		fp.dom = take(&a.domRules, d.uint(), d)
		for j := range fp.dom {
			rule := &fp.dom[j]
			si := d.uint()
			if si >= len(selectors) {
				d.fail("selector index out of range")
			}
			rule.sel = &selectors[si]
			rule.checks = take(&a.domChecks, d.uint(), d)
			for k := range rule.checks {
				check := &rule.checks[k]
				check.name = d.str()
				check.pattern = pattern()
			}
		}
	}
	if d.pos != len(data) || d.tpos != len(text) {
		d.fail("trailing data")
	}
	return f, nil
}

// decodeAlloc holds the preallocated backing arrays of the decoded lists.
type decodeAlloc struct {
	literalSets [][]string
	literals    []string
	cats        []int
	names       []string
	keyed       []keyedPattern
	patternRefs []*ParsedPattern
	multiKeyed  []keyedPatterns
	domRules    []domRule
	domChecks   []domCheck
}

// take returns the next n elements of *buf, or nil if n is 0, capped so
// appending to them can't overwrite the elements that follow.
func take[T any](buf *[]T, n int, d *decoder) []T {
	if n == 0 {
		return nil
	}
	if n > len(*buf) {
		d.fail("counts too small")
	}
	s := (*buf)[:n:n]
	*buf = (*buf)[n:]
	return s
}

// takeNonNil is take, but returns an empty slice rather than nil if n is 0.
func takeNonNil[T any](buf *[]T, n int, d *decoder) []T {
	if n == 0 {
		return []T{}
	}
	return take(buf, n, d)
}

type decodeError string

func (e decodeError) Error() string { return string(e) }

// decoder reads uvarints from data and the bytes of strings from text.
type decoder struct {
	data string
	pos  int
	text string
	tpos int
}

func (d *decoder) fail(msg string) {
	panic(decodeError(fmt.Sprintf("decoding fingerprints at offset %d (text %d): %s", d.pos, d.tpos, msg)))
}

func (d *decoder) uint() int {
	var v uint64
	for shift := uint(0); ; shift += 7 {
		if d.pos >= len(d.data) || shift > 56 {
			d.fail("bad uvarint")
		}
		b := d.data[d.pos]
		d.pos++
		v |= uint64(b&0x7f) << shift
		if b < 0x80 {
			break
		}
	}
	if v > 1<<31 {
		d.fail("value out of range")
	}
	return int(v)
}

func (d *decoder) str() string {
	n := d.uint()
	if n > len(d.text)-d.tpos {
		d.fail("string out of range")
	}
	s := d.text[d.tpos : d.tpos+n]
	d.tpos += n
	return s
}

// literalSets decodes n literal sets.
func (d *decoder) literalSets(a *decodeAlloc, n int) [][]string {
	sets := take(&a.literalSets, n, d)
	if sets == nil {
		// Keep an empty list distinct from nil, which means unknown
		// literals for selectors.
		return [][]string{}
	}
	for i := range sets {
		sets[i] = take(&a.literals, d.uint(), d)
		for j := range sets[i] {
			sets[i][j] = d.str()
		}
	}
	return sets
}
