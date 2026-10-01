package profiler

import (
	"strings"
	"sync"

	"github.com/PuerkitoBio/goquery"
	"github.com/andybalholm/cascadia"
	"golang.org/x/net/html"
)

// domSelector is a dom selector, compiled on first use instead of on every
// doc.Find call.
type domSelector struct {
	selector string
	literals [][]string // see selectorLiterals and newDOMSelector

	once    sync.Once
	matcher goquery.Matcher // nil if the selector is invalid
}

// maxDOMLiteral bounds the length of the selector literals indexed. A prefix
// of a literal is present whenever the literal is, so truncating is safe; it
// filters nearly as well and makes the literal matcher much smaller.
const maxDOMLiteral = 12

// newDOMSelector returns selector with its literals.
func newDOMSelector(selector string) *domSelector {
	sel := &domSelector{selector: selector, literals: selectorLiterals(selector)}
	for _, part := range sel.literals {
		for i, lit := range part {
			if len(lit) > maxDOMLiteral {
				part[i] = lit[:maxDOMLiteral]
			}
		}
	}
	return sel
}

// compiled returns the compiled selector, or nil if it is invalid. It is
// safe for concurrent use.
func (sel *domSelector) compiled() goquery.Matcher {
	sel.once.Do(func() {
		// Like goquery's Find, treat invalid selectors as matching nothing.
		if m, err := cascadia.Compile(sel.selector); err == nil {
			sel.matcher = m
		}
	})
	return sel.matcher
}

// mayMatch reports whether, according to has, some element may match sel.
func (sel *domSelector) mayMatch(has func(lit string) bool) bool {
	if sel.literals == nil {
		return true
	}
	for _, part := range sel.literals {
		all := true
		for _, lit := range part {
			if !has(lit) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// addAttributeValues records the literals in the attribute values of n and
// its descendants.
func addAttributeValues(p *literalPresence, n *html.Node) {
	if n.Type == html.ElementNode {
		for _, attr := range n.Attr {
			p.add(attr.Val)
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		addAttributeValues(p, c)
	}
}

// analyzeDOM matches the dom rules against doc. As in wappalyzer, each
// check of a rule ("exists", "text" or an attribute) that passes for some
// element the selector finds is a detection of its own, with the
// confidence and version of its pattern.
func (s *Wappalyze) analyzeDOM(doc *goquery.Document) []matchPartResult {
	var technologies []matchPartResult

	// Find which selector literals occur in the document's attribute values,
	// so selectors that can't match needn't be run.
	has := func(lit string) bool { return true }
	if m := s.fingerprints.domLiteralMatcher(); m != nil {
		p := m.presence()
		for _, n := range doc.Nodes {
			addAttributeValues(p, n)
		}
		has = p.has
	}

	texts := make(elementTexts)
	for _, fingerprint := range s.fingerprints.Apps {
		for _, rule := range fingerprint.dom {
			if !rule.sel.mayMatch(has) {
				continue
			}
			matcher := rule.sel.compiled()
			if matcher == nil {
				continue
			}
			elements := doc.FindMatcher(matcher)
			if elements.Length() == 0 {
				continue
			}
			for _, check := range rule.checks {
				if ok, version := s.domCheck(elements, check, texts); ok {
					technologies = append(technologies, newMatch(fingerprint.name, check.pattern, version))
				}
			}
		}
	}
	return technologies
}

// domCheck reports whether check passes for one of elements, and the
// version it yields. texts caches the text of elements.
func (s *Wappalyze) domCheck(elements *goquery.Selection, check domCheck, texts elementTexts) (matched bool, version string) {
	if check.name == "exists" {
		return check.pattern.Evaluate("", s.regexTimeout)
	}
	for _, n := range elements.Nodes {
		var value string
		var has func(string) bool
		if check.name == "text" {
			t := texts.get(n)
			value, has = t.text, t.has
		} else {
			var ok bool
			if value, ok = attr(n, check.name); !ok {
				continue
			}
			if len(value) >= minDOMPrefilterLen {
				has = containsFunc(prefilterInput(value))
			}
		}
		if has != nil && !check.pattern.mayMatch(has) {
			continue
		}
		if matched, version = check.pattern.Evaluate(value, s.regexTimeout); matched {
			return matched, version
		}
	}
	return false, ""
}

// attr returns the value of n's attribute key.
func attr(n *html.Node, key string) (string, bool) {
	for _, a := range n.Attr {
		if a.Namespace == "" && a.Key == key {
			return a.Val, true
		}
	}
	return "", false
}

// minDOMPrefilterLen is the length of the shortest dom value whose
// pattern's prefilter is checked before running its regex. For shorter
// values the regex is about as cheap.
const minDOMPrefilterLen = 256

// containsFunc returns a function reporting whether s contains a string.
func containsFunc(s string) func(string) bool {
	return func(sub string) bool { return strings.Contains(s, sub) }
}

// elementText is the text of an element as matched by dom text checks.
type elementText struct {
	text string
	// has reports whether a prefilter literal occurs in text, or is nil
	// if text is too short for prefiltering to pay off.
	has func(string) bool
}

// elementTexts caches the text of elements, which many checks may inspect.
type elementTexts map[*html.Node]*elementText

func (texts elementTexts) get(n *html.Node) *elementText {
	t := texts[n]
	if t == nil {
		t = &elementText{text: strings.TrimSpace(nodeText(n))}
		if len(t.text) >= minDOMPrefilterLen {
			t.has = containsFunc(prefilterInput(t.text))
		}
		texts[n] = t
	}
	return t
}

// nodeText returns the text of n and its descendants, like goquery's Text.
func nodeText(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return b.String()
}

// metaValues returns the content of the meta tags of doc, keyed by their
// lowercased name, property and http-equiv attributes. Every value of a
// key is kept, including empty ones: a pattern for a meta tag may only
// require it to exist.
func metaValues(doc *goquery.Document) map[string][]string {
	meta := make(map[string][]string)
	doc.Find("meta").Each(func(_ int, el *goquery.Selection) {
		content, _ := el.Attr("content")
		var keys [3]string
		for i, attr := range [...]string{"name", "property", "http-equiv"} {
			key, ok := el.Attr(attr)
			if !ok {
				continue
			}
			key = strings.ToLower(strings.TrimSpace(key))
			if key == "" || key == keys[0] || key == keys[1] {
				continue
			}
			keys[i] = key
			meta[key] = append(meta[key], content)
		}
	})
	return meta
}
