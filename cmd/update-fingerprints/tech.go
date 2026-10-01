package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Tech is a technology in kitsune's format, as written to
// assets/fingerprints_data.json. Every field has one shape (the sources allow
// a string or a list in many places), list fields are sorted, and map keys
// that are case-insensitive are lowercased.
//
// The fields are in the order they are written.
type Tech struct {
	Cats             []int                `json:"cats,omitempty"`
	CSS              []string             `json:"css,omitempty"`
	DOM              map[string]*DOMCheck `json:"dom,omitempty"`
	Cookies          map[string]string    `json:"cookies,omitempty"`
	JS               map[string]string    `json:"js,omitempty"`
	Headers          map[string]string    `json:"headers,omitempty"`
	HTML             []string             `json:"html,omitempty"`
	Text             []string             `json:"text,omitempty"`
	Scripts          []string             `json:"scripts,omitempty"`
	ScriptSrc        []string             `json:"scriptSrc,omitempty"`
	URL              []string             `json:"url,omitempty"`
	XHR              []string             `json:"xhr,omitempty"`
	Robots           []string             `json:"robots,omitempty"`
	CertIssuer       []string             `json:"certIssuer,omitempty"`
	Meta             map[string][]string  `json:"meta,omitempty"`
	DNS              map[string][]string  `json:"dns,omitempty"`
	Probe            map[string]string    `json:"probe,omitempty"`
	Implies          []string             `json:"implies,omitempty"`
	Requires         []string             `json:"requires,omitempty"`
	RequiresCategory []int                `json:"requiresCategory,omitempty"`
	Excludes         []string             `json:"excludes,omitempty"`
	Description      string               `json:"description,omitempty"`
	Website          string               `json:"website,omitempty"`
	CPE              string               `json:"cpe,omitempty"`
	Icon             string               `json:"icon,omitempty"`
}

// DOMCheck holds the checks of the elements matching a dom selector. An
// element matches if every check present passes. Exists and Text are
// pointers since "" is a meaningful value (any element, any text).
type DOMCheck struct {
	Exists     *string           `json:"exists,omitempty"`
	Text       *string           `json:"text,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	// Properties are checks of JS properties of the element, which static
	// HTML doesn't have. They are kept as they are; the engine ignores
	// them.
	Properties map[string]any `json:"properties,omitempty"`
}

// existsCheck returns the check that just requires an element to exist.
func existsCheck() *DOMCheck {
	s := ""
	return &DOMCheck{Exists: &s}
}

// isExistsOnly reports whether c only requires an element to exist.
func (c *DOMCheck) isExistsOnly() bool {
	return c.Exists != nil && *c.Exists == "" && c.Text == nil && len(c.Attributes) == 0 && len(c.Properties) == 0
}

// empty reports whether c has no checks at all.
func (c *DOMCheck) empty() bool {
	return c.Exists == nil && c.Text == nil && len(c.Attributes) == 0 && len(c.Properties) == 0
}

func (c *DOMCheck) clone() *DOMCheck {
	out := &DOMCheck{Exists: c.Exists, Text: c.Text}
	if c.Attributes != nil {
		out.Attributes = make(map[string]string, len(c.Attributes))
		for k, v := range c.Attributes {
			out.Attributes[k] = v
		}
	}
	if c.Properties != nil {
		out.Properties = make(map[string]any, len(c.Properties))
		for k, v := range c.Properties {
			out.Properties[k] = v
		}
	}
	return out
}

// rawTech is a technology in the Wappalyzer source format, which allows a
// string or a list for most fields, and a string, list or object for dom.
// Fields kitsune doesn't use (oss, saas, pricing) are ignored.
type rawTech struct {
	Cats             intList               `json:"cats"`
	CSS              stringList            `json:"css"`
	DOM              json.RawMessage       `json:"dom"`
	Cookies          map[string]string     `json:"cookies"`
	JS               map[string]string     `json:"js"`
	Headers          map[string]string     `json:"headers"`
	HTML             stringList            `json:"html"`
	Text             stringList            `json:"text"`
	Scripts          stringList            `json:"scripts"`
	ScriptSrc        stringList            `json:"scriptSrc"`
	URL              stringList            `json:"url"`
	XHR              stringList            `json:"xhr"`
	Robots           stringList            `json:"robots"`
	CertIssuer       stringList            `json:"certIssuer"`
	Meta             map[string]stringList `json:"meta"`
	DNS              map[string]stringList `json:"dns"`
	Probe            map[string]string     `json:"probe"`
	Implies          stringList            `json:"implies"`
	Requires         stringList            `json:"requires"`
	RequiresCategory intList               `json:"requiresCategory"`
	Excludes         stringList            `json:"excludes"`
	Description      string                `json:"description"`
	Website          string                `json:"website"`
	CPE              string                `json:"cpe"`
	Icon             string                `json:"icon"`

	// Comment documents an entry of the overrides file.
	Comment string `json:"_comment"`
}

// stringList is a list of strings that may be written as a single string.
// Elements that aren't strings are skipped.
type stringList []string

func (l *stringList) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*l = stringList{s}
		return nil
	}
	var items []any
	if err := json.Unmarshal(data, &items); err != nil {
		return fmt.Errorf("want a string or a list of strings, got %s", data)
	}
	*l = stringList{}
	for _, item := range items {
		if s, ok := item.(string); ok {
			*l = append(*l, s)
		}
	}
	return nil
}

// intList is a list of ints that may be written as a single int.
type intList []int

func (l *intList) UnmarshalJSON(data []byte) error {
	var n int
	if err := json.Unmarshal(data, &n); err == nil {
		*l = intList{n}
		return nil
	}
	var items []int
	if err := json.Unmarshal(data, &items); err != nil {
		return fmt.Errorf("want an int or a list of ints, got %s", data)
	}
	*l = items
	return nil
}

// normalizer turns rawTechs into Techs, counting what it does.
type normalizer struct {
	stats counter
	// split controls whether exists-only dom selector lists are split into
	// their selectors (see normalizeDOM).
	split bool
}

// normalize returns raw in kitsune's format. It fails only if the dom
// field is malformed.
func (n *normalizer) normalize(raw *rawTech) (*Tech, error) {
	t := &Tech{
		Cats:             append([]int(nil), raw.Cats...),
		CSS:              sortedSet(raw.CSS),
		HTML:             sortedSet(raw.HTML),
		Text:             sortedSet(raw.Text),
		Scripts:          sortedSet(raw.Scripts),
		ScriptSrc:        sortedSet(raw.ScriptSrc),
		URL:              sortedSet(raw.URL),
		XHR:              sortedSet(raw.XHR),
		Robots:           sortedSet(raw.Robots),
		CertIssuer:       sortedSet(raw.CertIssuer),
		Implies:          sortedSet(raw.Implies),
		Requires:         sortedSet(raw.Requires),
		RequiresCategory: append([]int(nil), raw.RequiresCategory...),
		Excludes:         sortedSet(raw.Excludes),
		Description:      raw.Description,
		Website:          raw.Website,
		CPE:              raw.CPE,
		Icon:             raw.Icon,
	}
	// Cookie, header and meta names are case-insensitive; JS globals and
	// DNS record types are not, though record types are conventionally
	// upper case.
	t.Cookies = n.keyed("cookies", raw.Cookies, strings.ToLower)
	t.Headers = n.keyed("headers", raw.Headers, strings.ToLower)
	t.JS = n.keyed("js", raw.JS, nil)
	t.Meta = n.multiKeyed(raw.Meta, strings.ToLower)
	t.DNS = n.multiKeyed(raw.DNS, strings.ToUpper)
	if len(raw.Probe) > 0 {
		t.Probe = make(map[string]string, len(raw.Probe))
		for k, v := range raw.Probe {
			t.Probe[k] = v
		}
	}
	dom, err := n.normalizeDOM(raw.DOM)
	if err != nil {
		return nil, fmt.Errorf("dom: %w", err)
	}
	t.DOM = dom
	return t, nil
}

// keyed normalizes a map of one pattern per key, merging keys that are
// equal once folded.
func (n *normalizer) keyed(field string, raw map[string]string, fold func(string) string) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string]string, len(raw))
	for _, key := range sortedKeys(raw) {
		k := key
		if fold != nil {
			k = fold(key)
		}
		if cur, ok := out[k]; ok {
			out[k] = combinePatterns(cur, raw[key], field, n.stats)
		} else {
			out[k] = raw[key]
		}
	}
	return out
}

// multiKeyed normalizes a map of pattern lists. A key whose patterns
// include "" just requires the key to exist, written as an empty list.
func (n *normalizer) multiKeyed(raw map[string]stringList, fold func(string) string) map[string][]string {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string][]string, len(raw))
	for _, key := range sortedKeys(raw) {
		k := fold(key)
		out[k] = unionKeyed(out[k], hasKey(out, k), raw[key])
	}
	return out
}

// unionKeyed returns the sorted union of the patterns of a key, cur, and
// add, where an empty list or a "" pattern means the key just has to
// exist; existence absorbs any pattern. seen reports whether cur is set.
func unionKeyed(cur []string, seen bool, add []string) []string {
	if seen && len(cur) == 0 || len(add) == 0 {
		return []string{}
	}
	for _, p := range add {
		if p == "" {
			return []string{}
		}
	}
	return sortedSet(union(cur, add))
}

func hasKey[V any](m map[string]V, k string) bool {
	_, ok := m[k]
	return ok
}

// normalizeDOM returns the dom rules in their object form, {selector:
// checks}. A selector, or a list of them, is short for each selector with
// {"exists": ""}.
//
// If n.split is set, the selector lists of exists-only rules are split on
// their top-level commas: "a, b" exists iff a or b does, and splitting lets
// equal rules from different sources dedupe.
func (n *normalizer) normalizeDOM(data json.RawMessage) (map[string]*DOMCheck, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || string(data) == "null" {
		return nil, nil
	}
	checks := make(map[string]*DOMCheck)
	var list stringList
	if data[0] != '{' {
		if err := json.Unmarshal(data, &list); err != nil {
			return nil, err
		}
		for _, sel := range list {
			checks[sel] = existsCheck()
		}
	} else {
		var obj map[string]map[string]any
		if err := json.Unmarshal(data, &obj); err != nil {
			return nil, err
		}
		for sel, raw := range obj {
			checks[sel] = n.domCheck(raw)
		}
	}
	// Selectors can't have modifiers; those of the source format's
	// selector strings go on the exists check.
	for _, sel := range sortedKeys(checks) {
		if !strings.Contains(sel, `\;`) {
			continue
		}
		c := checks[sel]
		delete(checks, sel)
		mods := modifiers(sel)
		sel = strings.TrimSpace(regexPart(sel))
		exists := mods
		if c.Exists != nil {
			exists = *c.Exists + mods
		}
		c.Exists = &exists
		checks[sel] = c
		n.stats["dom: modifiers moved from the selector to the exists check"]++
	}
	if !n.split {
		return checks, nil
	}
	out := make(map[string]*DOMCheck, len(checks))
	for _, sel := range sortedKeys(checks) {
		c := checks[sel]
		if !c.isExistsOnly() {
			if cur, ok := out[sel]; ok {
				out[sel] = mergeDOMCheck(cur, c, n.stats)
			} else {
				out[sel] = c
			}
			continue
		}
		parts := splitSelector(sel)
		if len(parts) > 1 {
			n.stats["dom: selector lists split"]++
		}
		for _, part := range parts {
			if _, ok := out[part]; !ok {
				out[part] = existsCheck()
			}
		}
	}
	return out, nil
}

// domCheck converts the checks of a selector from the source format.
// "attributes" maps attribute names to patterns; any other key that isn't a
// known check is an attribute too.
func (n *normalizer) domCheck(raw map[string]any) *DOMCheck {
	c := &DOMCheck{}
	for _, key := range sortedKeys(raw) {
		v := raw[key]
		switch key {
		case "exists":
			s, _ := v.(string)
			c.Exists = &s
		case "text":
			s, _ := v.(string)
			c.Text = &s
		case "properties":
			if m, ok := v.(map[string]any); ok {
				c.Properties = m
			}
		case "attributes":
			m, _ := v.(map[string]any)
			for name, p := range m {
				if s, ok := p.(string); ok {
					c.setAttribute(name, s)
				}
			}
		default:
			if s, ok := v.(string); ok {
				n.stats["dom: bare attribute checks moved into attributes"]++
				c.setAttribute(key, s)
			}
		}
	}
	if len(raw) == 0 {
		// {} just requires an element to exist.
		return existsCheck()
	}
	return c
}

func (c *DOMCheck) setAttribute(name, pattern string) {
	if c.Attributes == nil {
		c.Attributes = make(map[string]string)
	}
	c.Attributes[strings.ToLower(name)] = pattern
}

// splitSelector splits a CSS selector list on its top-level commas: those
// outside brackets, parentheses and quotes.
func splitSelector(sel string) []string {
	var parts []string
	var quote rune
	depth, start := 0, 0
	for i, r := range sel {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '\'' || r == '"':
			quote = r
		case r == '[' || r == '(':
			depth++
		case r == ']' || r == ')':
			depth--
		case r == ',' && depth == 0:
			parts = append(parts, sel[start:i])
			start = i + 1
		}
	}
	parts = append(parts, sel[start:])
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// sortedSet returns the distinct elements of l, sorted, or nil if there are
// none.
func sortedSet(l []string) []string {
	if len(l) == 0 {
		return nil
	}
	out := union(nil, l)
	sort.Strings(out)
	return out
}

// union returns a with the elements of b it lacks appended.
func union(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, l := range [][]string{a, b} {
		for _, s := range l {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}

func unionInts(a, b []int) []int {
	out := append([]int(nil), a...)
	for _, n := range b {
		found := false
		for _, m := range out {
			found = found || m == n
		}
		if !found {
			out = append(out, n)
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// counter counts events by description.
type counter map[string]int

// regexPart returns the regex of a pattern, without its \; modifiers.
func regexPart(pattern string) string {
	re, _, _ := strings.Cut(pattern, `\;`)
	return re
}

// modifiers returns the \; modifiers of a pattern, including the leading
// \;, or "".
func modifiers(pattern string) string {
	if i := strings.Index(pattern, `\;`); i >= 0 {
		return pattern[i:]
	}
	return ""
}
