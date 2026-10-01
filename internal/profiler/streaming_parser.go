package profiler

import (
	"bytes"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// Limits on what of a page is matched, as in wappalyzer's content script.
const (
	// maxInlineScripts and maxInlineScriptChars bound the inline scripts
	// matched against scripts patterns.
	maxInlineScripts     = 50
	maxInlineScriptChars = 200000
	// maxTextChars bounds the visible text matched against text patterns.
	maxTextChars = 25000
)

// analyzeHTML parses body and matches it: the html, its meta tags, dom,
// script srcs, inline scripts and styles, and visible text. Script and
// stylesheet URLs, resolved against base (the URL of the page, which may be
// nil), are sent to fetcher. It returns the matches and the page title.
func (s *Wappalyze) analyzeHTML(body []byte, base *url.URL, fetcher *AssetFetcher) ([]matchPartResult, string) {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return nil, ""
	}
	if href, ok := doc.Find("base[href]").First().Attr("href"); ok && base != nil {
		if ref, err := base.Parse(strings.TrimSpace(href)); err == nil {
			base = ref
		}
	}
	f := s.fingerprints
	var technologies []matchPartResult

	var inline strings.Builder
	inlineCount := 0
	doc.Find("script").Each(func(_ int, el *goquery.Selection) {
		if src, ok := el.Attr("src"); ok {
			src = strings.TrimSpace(src)
			if src == "" || strings.HasPrefix(src, "data:") {
				return
			}
			// Match the src as the browser sees it, resolved against
			// the page URL, and as written, which some patterns expect.
			abs := resolveURL(base, src)
			if abs != "" {
				fetcher.AddURL(abs, "script", 5)
				technologies = append(technologies, f.matchString(abs, scriptSrcPart, s.regexTimeout)...)
			}
			if abs != src {
				technologies = append(technologies, f.matchString(src, scriptSrcPart, s.regexTimeout)...)
			}
			return
		}
		code := el.Text()
		if code == "" {
			return
		}
		if inlineCount < maxInlineScripts && inline.Len() < maxInlineScriptChars {
			inlineCount++
			if inline.Len() > 0 {
				inline.WriteByte(',')
			}
			inline.WriteString(code[:min(len(code), maxInlineScriptChars-inline.Len())])
		}
		if kind, _ := el.Attr("type"); isJavaScriptType(kind) {
			technologies = append(technologies, f.matchJSGlobals(code, !strings.EqualFold(strings.TrimSpace(kind), "module"))...)
		}
	})
	if inline.Len() > 0 {
		technologies = append(technologies, f.matchString(inline.String(), scriptPart, s.regexTimeout)...)
	}

	doc.Find("link[href]").Each(func(_ int, el *goquery.Selection) {
		if rel, _ := el.Attr("rel"); !hasToken(rel, "stylesheet") {
			return
		}
		href, _ := el.Attr("href")
		if abs := resolveURL(base, strings.TrimSpace(href)); abs != "" {
			fetcher.AddURL(abs, "style", 3)
		}
	})

	var styles strings.Builder
	doc.Find("style").Each(func(_ int, el *goquery.Selection) {
		styles.WriteString(el.Text())
		styles.WriteByte('\n')
	})
	if styles.Len() > 0 {
		technologies = append(technologies, f.matchString(styles.String(), cssPart, s.regexTimeout)...)
	}

	technologies = append(technologies, f.matchKeyValues(metaValues(doc), metaPart, s.regexTimeout)...)
	technologies = append(technologies, s.analyzeDOM(doc)...)
	technologies = append(technologies, f.matchString(strings.ToLower(string(body)), htmlPart, s.regexTimeout)...)
	if text := visibleText(doc, maxTextChars); text != "" {
		technologies = append(technologies, f.matchString(text, textPart, s.regexTimeout)...)
	}

	title := strings.TrimSpace(doc.Find("title").First().Text())
	return technologies, title
}

// resolveURL returns ref resolved against base if that gives an absolute
// http(s) URL, or "".
func resolveURL(base *url.URL, ref string) string {
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	if base != nil {
		u = base.ResolveReference(u)
	}
	if u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
		return ""
	}
	return u.String()
}

// hasToken reports whether the space-separated list s contains token,
// ignoring case.
func hasToken(s, token string) bool {
	for _, t := range strings.Fields(s) {
		if strings.EqualFold(t, token) {
			return true
		}
	}
	return false
}

// isJavaScriptType reports whether a script element of the given type
// attribute is run as JavaScript.
func isJavaScriptType(kind string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "", "module", "text/javascript", "application/javascript", "text/ecmascript", "application/ecmascript":
		return true
	}
	return false
}

// visibleText returns roughly the text of doc's body a browser would
// render, with whitespace collapsed, up to max bytes: the text outside
// scripts, styles, templates and elements marked hidden.
func visibleText(doc *goquery.Document, max int) string {
	body := doc.Find("body").First()
	if body.Length() == 0 {
		return ""
	}
	var b strings.Builder
	space := false
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		for c := n.FirstChild; c != nil && b.Len() < max; c = c.NextSibling {
			switch c.Type {
			case html.TextNode:
				for _, word := range strings.Fields(c.Data) {
					if space && b.Len() > 0 {
						b.WriteByte(' ')
					}
					b.WriteString(word)
					space = true
				}
				if c.Data != "" && !isSpace(c.Data[len(c.Data)-1]) {
					space = false
				}
			case html.ElementNode:
				switch c.DataAtom {
				case atom.Script, atom.Style, atom.Noscript, atom.Template, atom.Head, atom.Svg, atom.Iframe, atom.Object:
					continue
				}
				if hiddenElement(c) {
					continue
				}
				space = true
				walk(c)
				space = true
			}
		}
	}
	walk(body.Nodes[0])
	text := b.String()
	if len(text) > max {
		text = text[:max]
	}
	return text
}

// hiddenElement reports whether n is marked hidden in the markup.
func hiddenElement(n *html.Node) bool {
	for _, attr := range n.Attr {
		switch attr.Key {
		case "hidden":
			return true
		case "style":
			style := strings.ReplaceAll(strings.ToLower(attr.Val), " ", "")
			if strings.Contains(style, "display:none") || strings.Contains(style, "visibility:hidden") {
				return true
			}
		}
	}
	return false
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}
