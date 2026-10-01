package profiler

import (
	"regexp/syntax"
	"sort"
	"strings"
	"unicode/utf8"
	"unsafe"
)

// Literal prefiltering.
//
// Go's regexp has no DFA, so a regex without a literal prefix steps an NFA
// over every byte of its input even when it cannot possibly match. For large
// inputs (HTML bodies, CSS and JS assets) that dominates analysis time. Most
// regexes, however, require certain literal substrings to be present in any
// match. Checking for those first lets us skip the regex entirely; results
// are unchanged because a regex is only skipped when it cannot match.

// maxLiterals bounds the size of the literal sets tracked while analysing a
// regex. Larger sets are dropped (treated as "unknown"), which is always safe.
const maxLiterals = 16

// maxLiteralSets bounds how many independent literal sets are kept per regex.
const maxLiteralSets = 3

// minScanLen is the input size above which it's cheaper to find all literals
// of a literalMatcher in one pass than to search for each one separately.
const minScanLen = 4 << 10

// foldHazard is the only non-ASCII rune whose simple case fold is an ASCII
// letter but whose lowercase form is not ('ſ' folds to 's'). An input
// containing it must have it replaced for case-insensitive prefilters (see
// prefilterInput).
const foldHazard = "ſ"

// prefilterInput returns s in the form prefilter literals are checked
// against: lowercased, with foldHazard replaced by the 's' it folds to, so
// that every literal a case-insensitive match contains occurs in it. ToLower
// doesn't allocate if s is already lowercase.
func prefilterInput(s string) string {
	lowered := strings.ToLower(s)
	if strings.Contains(lowered, foldHazard) {
		lowered = strings.ReplaceAll(lowered, foldHazard, "s")
	}
	return lowered
}

// asciiLower returns s with its ASCII letters lowercased, so offsets in it
// are offsets in s, and whether s has a foldHazard: 'ſ' or the Kelvin sign
// 'K', which a case-insensitive regex matches as 's' or 'k'. For a string
// without them it can stand in for prefilterInput, as prefilter literals
// are ASCII (see requiredLiterals), and the lowered regexes of patterns
// match it (see ParsedPattern.loweredRe).
func asciiLower(s string) (lowered string, hazard bool) {
	i := 0
	for ; i < len(s); i++ {
		if c := s[i]; 'A' <= c && c <= 'Z' || c >= utf8.RuneSelf {
			break
		}
	}
	if i == len(s) {
		return s, false
	}
	b := make([]byte, len(s))
	copy(b, s[:i])
	for ; i < len(s); i++ {
		c := s[i]
		switch {
		case 'A' <= c && c <= 'Z':
			c += 'a' - 'A'
		case c == 0xc5: // ſ is C5 BF
			hazard = hazard || i+1 < len(s) && s[i+1] == 0xbf
		case c == 0xe2: // K is E2 84 AA
			hazard = hazard || i+2 < len(s) && s[i+1] == 0x84 && s[i+2] == 0xaa
		}
		b[i] = c
	}
	return unsafe.String(&b[0], len(b)), hazard
}

// literalSets lists literal sets that are each required by a regex: every
// match contains at least one literal from every set. nil means no
// constraint is known.
type literalSets [][]string

// satisfied reports whether, according to has, at least one literal of every
// set is present.
func (sets literalSets) satisfied(has func(lit string) bool) bool {
	for _, set := range sets {
		found := false
		for _, lit := range set {
			if has(lit) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// in reports whether s contains at least one literal of every set.
func (sets literalSets) in(s string) bool {
	return sets.satisfied(func(lit string) bool { return strings.Contains(s, lit) })
}

// literalMatcher finds which of a fixed set of literals occur in an input in
// a single pass (Aho-Corasick), instead of one strings.Contains per literal.
type literalMatcher struct {
	ids     map[string]int32
	classes [256]int32 // byte -> column in delta; 0 for bytes in no literal
	width   int        // number of byte classes
	delta   []int32    // state*width + class -> next state
	out     [][]int32  // state -> ids of literals ending here
}

// newLiteralMatcher returns a matcher for lits, or nil if there are none.
func newLiteralMatcher(lits []string) *literalMatcher {
	m := &literalMatcher{ids: make(map[string]int32)}
	for _, lit := range lits {
		if _, ok := m.ids[lit]; !ok && lit != "" {
			m.ids[lit] = int32(len(m.ids))
		}
	}
	if len(m.ids) == 0 {
		return nil
	}
	m.width = 1
	for lit := range m.ids {
		for i := 0; i < len(lit); i++ {
			if m.classes[lit[i]] == 0 {
				m.classes[lit[i]] = int32(m.width)
				m.width++
			}
		}
	}

	// Build the trie; -1 marks a missing edge.
	newState := func() int32 {
		for i := 0; i < m.width; i++ {
			m.delta = append(m.delta, -1)
		}
		m.out = append(m.out, nil)
		return int32(len(m.out) - 1)
	}
	newState()
	for lit, id := range m.ids {
		s := int32(0)
		for i := 0; i < len(lit); i++ {
			edge := int(s)*m.width + int(m.classes[lit[i]])
			if m.delta[edge] < 0 {
				next := newState()
				m.delta[edge] = next
			}
			s = m.delta[edge]
		}
		m.out[s] = append(m.out[s], id)
	}

	// Turn it into a DFA by following failure links breadth-first.
	fail := make([]int32, len(m.out))
	var queue []int32
	for c := 0; c < m.width; c++ {
		if next := m.delta[c]; next < 0 {
			m.delta[c] = 0
		} else {
			queue = append(queue, next)
		}
	}
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		m.out[s] = append(m.out[s], m.out[fail[s]]...)
		for c := 0; c < m.width; c++ {
			edge := int(s)*m.width + c
			fallback := m.delta[int(fail[s])*m.width+c]
			if next := m.delta[edge]; next < 0 {
				m.delta[edge] = fallback
			} else {
				fail[next] = fallback
				queue = append(queue, next)
			}
		}
	}
	return m
}

// scan returns a function reporting whether a literal known to m occurs in s.
// Literals unknown to m are reported as present.
func (m *literalMatcher) scan(s string) func(lit string) bool {
	p := m.presence()
	p.add(s)
	return p.has
}

// foldCase makes m match ASCII letters case-insensitively. Its literals must
// be lowercase.
func (m *literalMatcher) foldCase() {
	for c := 'a'; c <= 'z'; c++ {
		m.classes[c-'a'+'A'] = m.classes[c]
	}
}

// literalPresence records which literals of a literalMatcher occur in any of
// the strings added to it.
type literalPresence struct {
	m       *literalMatcher
	present []bool
}

func (m *literalMatcher) presence() *literalPresence {
	return &literalPresence{m: m, present: make([]bool, len(m.ids))}
}

// add records the literals occurring in s.
func (p *literalPresence) add(s string) {
	m := p.m
	state := int32(0)
	for i := 0; i < len(s); i++ {
		state = m.delta[int(state)*m.width+int(m.classes[s[i]])]
		for _, id := range m.out[state] {
			p.present[id] = true
		}
	}
}

// has reports whether lit occurs in one of the added strings. Literals unknown
// to the matcher are reported as present.
func (p *literalPresence) has(lit string) bool {
	id, ok := p.m.ids[lit]
	return !ok || p.present[id]
}

type literalInfo struct {
	// exact is non-nil if every match is one of these strings.
	exact []string
	// all lists literal sets that are each required: every match contains
	// at least one literal from every set.
	all literalSets
}

// requiredLiterals returns literal sets that are each required by expr:
// every match of expr contains at least one literal from every set. It
// returns nil if no useful set could be derived.
//
// If lower is true the literals are lowercased and only ASCII literals are
// used, so the result can be checked against prefilterInput(input) for both
// case-sensitive and case-insensitive regexes. Otherwise case-insensitive parts of the regex are
// treated as unknown and the literals must be checked against the input as is.
func requiredLiterals(expr string, lower bool) literalSets {
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return nil
	}
	return analyzeLiterals(re, lower).all
}

func analyzeLiterals(re *syntax.Regexp, lower bool) literalInfo {
	switch re.Op {
	case syntax.OpLiteral:
		s := string(re.Rune)
		if lower {
			if !isASCII(s) {
				return literalInfo{}
			}
			s = strings.ToLower(s)
		} else if re.Flags&syntax.FoldCase != 0 {
			return literalInfo{}
		}
		return exactLiterals([]string{s})

	case syntax.OpCharClass:
		var set []string
		for i := 0; i+1 < len(re.Rune); i += 2 {
			lo, hi := re.Rune[i], re.Rune[i+1]
			if hi-lo >= maxLiterals {
				return literalInfo{}
			}
			for r := lo; r <= hi; r++ {
				if lower {
					if r >= 0x80 {
						return literalInfo{}
					}
					if 'A' <= r && r <= 'Z' {
						r += 'a' - 'A'
					}
				}
				set = addLiteral(set, string(r))
				if len(set) > maxLiterals {
					return literalInfo{}
				}
			}
		}
		if len(set) == 0 {
			return literalInfo{}
		}
		return exactLiterals(set)

	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine,
		syntax.OpBeginText, syntax.OpEndText, syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return literalInfo{exact: []string{""}}

	case syntax.OpCapture:
		return analyzeLiterals(re.Sub[0], lower)

	case syntax.OpPlus:
		return literalInfo{all: analyzeLiterals(re.Sub[0], lower).all}

	case syntax.OpRepeat:
		if re.Min >= 1 {
			return literalInfo{all: analyzeLiterals(re.Sub[0], lower).all}
		}
		return literalInfo{}

	case syntax.OpQuest:
		sub := analyzeLiterals(re.Sub[0], lower)
		if sub.exact != nil && len(sub.exact) < maxLiterals {
			return literalInfo{exact: addLiteral(append([]string(nil), sub.exact...), "")}
		}
		return literalInfo{}

	case syntax.OpAlternate:
		// A match satisfies one branch, so it contains a literal from the
		// union of one required set per branch.
		var exact, any []string
		exactOK, anyOK := true, true
		for _, sub := range re.Sub {
			info := analyzeLiterals(sub, lower)
			if exactOK && info.exact != nil {
				for _, s := range info.exact {
					exact = addLiteral(exact, s)
				}
				exactOK = len(exact) <= maxLiterals
			} else {
				exactOK = false
			}
			if best := bestLiterals(info.all); anyOK && best != nil {
				for _, s := range best {
					any = addLiteral(any, s)
				}
				anyOK = len(any) <= maxLiterals
			} else {
				anyOK = false
			}
		}
		var info literalInfo
		if exactOK {
			info.exact = exact
		}
		if anyOK {
			info.all = literalSets{any}
		}
		return info

	case syntax.OpConcat:
		// Every child's required sets are required by the concatenation.
		// Runs of consecutive exact children are also combined by cross
		// product (e.g. "http" "s?" "://" -> {"http://", "https://"}).
		var all literalSets
		add := func(set []string) {
			if usefulLiterals(set) {
				all = append(all, set)
			}
		}
		run := []string{""}
		allExact := true
		for _, sub := range re.Sub {
			info := analyzeLiterals(sub, lower)
			switch {
			case info.exact != nil && len(run)*len(info.exact) <= maxLiterals:
				run = crossLiterals(run, info.exact)
				continue
			case info.exact != nil:
				add(run)
				run = info.exact
			default:
				add(run)
				run = []string{""}
				for _, set := range info.all {
					add(set)
				}
			}
			allExact = false
		}
		add(run)
		info := literalInfo{all: pruneLiterals(all)}
		if allExact {
			info.exact = run
		}
		return info
	}
	return literalInfo{}
}

func exactLiterals(set []string) literalInfo {
	info := literalInfo{exact: set}
	if usefulLiterals(set) {
		info.all = literalSets{set}
	}
	return info
}

// usefulLiterals reports whether set constrains the input at all.
func usefulLiterals(set []string) bool {
	if len(set) == 0 {
		return false
	}
	for _, s := range set {
		if s == "" {
			return false
		}
	}
	return true
}

// pruneLiterals keeps the most selective maxLiteralSets sets, most selective
// first, so that satisfied can bail out early.
func pruneLiterals(sets literalSets) literalSets {
	sort.SliceStable(sets, func(i, j int) bool { return betterLiterals(sets[i], sets[j]) })
	if len(sets) > maxLiteralSets {
		sets = sets[:maxLiteralSets]
	}
	return sets
}

// bestLiterals returns the most selective of sets, or nil.
func bestLiterals(sets literalSets) []string {
	var best []string
	for _, set := range sets {
		if best == nil || betterLiterals(set, best) {
			best = set
		}
	}
	return best
}

// betterLiterals reports whether a is a more selective literal set than b:
// a longer shortest literal, or the same with fewer alternatives.
func betterLiterals(a, b []string) bool {
	ma, mb := minLen(a), minLen(b)
	if ma != mb {
		return ma > mb
	}
	return len(a) < len(b)
}

func minLen(set []string) int {
	m := -1
	for _, s := range set {
		if m < 0 || len(s) < m {
			m = len(s)
		}
	}
	return m
}

func crossLiterals(a, b []string) []string {
	out := make([]string, 0, len(a)*len(b))
	for _, x := range a {
		for _, y := range b {
			out = addLiteral(out, x+y)
		}
	}
	return out
}

func addLiteral(set []string, s string) []string {
	for _, v := range set {
		if v == s {
			return set
		}
	}
	return append(set, s)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// selectorLiterals returns, for each comma-separated selector in the CSS
// selector group sel, lowercase ASCII literals that every element matching
// it has in some attribute value: ids (#x), classes (.x) and attribute
// values ([k=x], [k*=x], ...). An element can therefore only match sel if,
// for some selector, all of its literals occur in attribute values of the
// document. It returns nil if some selector has no such literals, or if sel
// uses syntax this conservative scan doesn't understand (escapes, unbalanced
// brackets). Anything inside parentheses (:not(...), :contains(...), ...) is
// ignored.
func selectorLiterals(sel string) [][]string {
	var parts [][]string
	var lits []string
	depth := 0
	endPart := func() bool {
		if len(lits) == 0 {
			return false
		}
		parts = append(parts, lits)
		lits = nil
		return true
	}
	addLit := func(s string) {
		if s != "" && isASCII(s) {
			lits = addLiteral(lits, strings.ToLower(s))
		}
	}
	isIdent := func(c byte) bool {
		return c == '-' || c == '_' || c >= 0x80 ||
			'0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
	}
	ident := func(i int) int {
		for i < len(sel) && isIdent(sel[i]) {
			i++
		}
		return i
	}
	skipSpace := func(i int) int {
		for i < len(sel) && strings.IndexByte(" \t\n\r\f", sel[i]) >= 0 {
			i++
		}
		return i
	}
	// quoted returns the end of the quoted string starting at i, or -1.
	quoted := func(i int) int {
		end := strings.IndexByte(sel[i+1:], sel[i])
		if end < 0 {
			return -1
		}
		return i + 1 + end + 1
	}

	if strings.IndexByte(sel, '\\') >= 0 {
		return nil
	}
	for i := 0; i < len(sel); {
		switch c := sel[i]; {
		case c == '"' || c == '\'':
			if i = quoted(i); i < 0 {
				return nil
			}
		case c == '(':
			depth++
			i++
		case c == ')':
			if depth--; depth < 0 {
				return nil
			}
			i++
		case depth > 0:
			i++
		case c == ',':
			if !endPart() {
				return nil
			}
			i++
		case c == '#' || c == '.':
			end := ident(i + 1)
			addLit(sel[i+1 : end])
			i = end
		case c == '[':
			// [name], or [name op value flags] with the value quoted or
			// an identifier. Only the ops implying that the attribute
			// value contains the given value are used.
			i = skipSpace(ident(skipSpace(i + 1)))
			op := ""
			for _, o := range []string{"=", "~=", "|=", "^=", "$=", "*="} {
				if strings.HasPrefix(sel[i:], o) {
					op = o
				}
			}
			value := ""
			if op != "" {
				i = skipSpace(i + len(op))
				if i < len(sel) && (sel[i] == '"' || sel[i] == '\'') {
					end := quoted(i)
					if end < 0 {
						return nil
					}
					value, i = sel[i+1:end-1], end
				} else {
					end := ident(i)
					value, i = sel[i:end], end
				}
				i = skipSpace(i)
			}
			// Anything else before ']' (e.g. a case-insensitivity flag or
			// an unsupported op like != or #=(regex)) means the value can't
			// be used. Bail if the ']' found might not end the attribute.
			end := strings.IndexByte(sel[i:], ']')
			if end < 0 || strings.ContainsAny(sel[i:i+end], `"'()[`) {
				return nil
			}
			if end == 0 {
				addLit(value)
			}
			i += end + 1
		default:
			i++
		}
	}
	if depth != 0 || !endPart() {
		return nil
	}
	return parts
}
