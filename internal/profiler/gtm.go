package profiler

// Google Tag Manager containers.
//
// Many sites load their analytics and ad tags only through a GTM container:
// the page has the GTM snippet, and the tags are in the container JS
// (https://www.googletagmanager.com/gtm.js?id=GTM-XXXX) that the snippet
// loads. A container starts with its configuration as JSON,
//
//	var data = {"resource": {"macros": [...], "tags": [...], "predicates": [...], "rules": [...]},
//	            "runtime": [...], "permissions": {...}, ...};
//
// followed by the GTM runtime. The runtime is the same for every container
// and holds code and URLs for many Google products and for detecting others
// (WordPress, fls.doubleclick.net, ...), so it isn't matched. Only the
// configuration is read, and of it only what the container would run:
//
//   - Tags that are live. A tag paused in GTM is published as
//     {"function": "__paused"} without its settings, and a tag that no rule
//     adds has no trigger, so neither fires.
//   - For each live tag, a line "gtm:tag __<type> id:<id>...\n" with the
//     tag's template (__googtag, __awct, __hjtc, ...) and the Google ids
//     (G-, UA-, AW-, DC-, GT-) among its settings, following references to
//     variables (macros). These lines are matched as scripts, so
//     assets/overrides.json maps templates to techs with patterns like
//     "gtm:tag __awct ".
//   - The script URLs that a live tag's template may inject, from the
//     template's inject_script permission (as https://bat.bing.com/bat.js
//     for __baut, or https://connect.facebook.net/en_US/fbevents.js for a
//     community Meta Pixel template). They are matched as script srcs.
//   - The markup of live Custom HTML tags (__html), which GTM adds to the
//     page: it is matched as html, its script srcs as script srcs and its
//     inline scripts as scripts.
//
// gtag.js (googletagmanager.com/gtag/js?id=G-...) is a container of the same
// form, so page scripts from googletagmanager.com are read this way too.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"sort"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// googleTagOrigin is where containers are fetched from. Tests change it.
var googleTagOrigin = "https://www.googletagmanager.com"

const (
	// maxGTMContainers bounds the containers fetched for GTM ids found in
	// a page (gtm.js scripts of the page are fetched anyway).
	maxGTMContainers = 2
	// maxGTMBytes bounds what is read of a container. Reading stops at the
	// end of the configuration, which is 30-450KB; the runtime after it,
	// another 300-500KB, isn't read.
	maxGTMBytes = 1 << 20
	// maxGTMHTML bounds the Custom HTML matched per container.
	maxGTMHTML = 256 << 10
	// maxGTMIDs bounds the ids listed per tag, and maxGTMDepth the depth
	// of variable references followed to find them.
	maxGTMIDs   = 8
	maxGTMDepth = 4
)

// gtmEvidence is what a container is matched by.
type gtmEvidence struct {
	tags          string   // "gtm:tag ..." lines, matched as scripts
	scriptSrcs    []string // injected script URLs, matched as script srcs
	html          []string // Custom HTML, matched as html
	inlineScripts []string // scripts of the Custom HTML, matched as scripts
}

// gtmContainerIDs returns the GTM container ids that body refers to, at most
// max, in order: in the snippet ('GTM-XXXX' as an argument), its noscript
// iframe (ns.html?id=GTM-XXXX), a gtm.js URL (gtm.js?id=GTM-XXXX), or quoted
// in markup or settings (data-gtm-container-id="GTM-XXXX"). An id must be
// quoted or follow id=, so prose mentioning GTM- doesn't count.
func gtmContainerIDs(body []byte, max int) []string {
	var ids []string
	for i := 0; len(ids) < max; {
		j := bytes.Index(body[i:], []byte("GTM-"))
		if j < 0 {
			break
		}
		start := i + j
		end := start + len("GTM-")
		for end < len(body) && end-start < 16 && isGTMIDChar(body[end]) {
			end++
		}
		i = end
		if n := end - start - len("GTM-"); n < 4 || n > 12 {
			continue
		}
		before := byte(0)
		if start > 0 {
			before = body[start-1]
		}
		after := byte(0)
		if end < len(body) {
			after = body[end]
		}
		quoted := (before == '"' || before == '\'') && after == before ||
			before == '=' && start >= 3 && string(body[start-3:start]) == "id=" && !isGTMIDChar(after) && after != '-' ||
			// Quotes escaped in a JS string or JSON.
			before == '"' && start >= 2 && body[start-2] == '\\' && after == '\\'
		if !quoted {
			continue
		}
		id := string(body[start:end])
		dup := false
		for _, seen := range ids {
			dup = dup || seen == id
		}
		if !dup {
			ids = append(ids, id)
		}
	}
	return ids
}

func isGTMIDChar(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// gtmContainerURL returns the URL of the container with the given id.
func gtmContainerURL(id string) string {
	return googleTagOrigin + "/gtm.js?id=" + id
}

// googleTagKey returns a key identifying the container that rawURL loads,
// if it is a gtm.js or gtag.js URL of googleTagOrigin, or "".
func googleTagKey(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	origin, err := url.Parse(googleTagOrigin)
	if err != nil || !strings.EqualFold(u.Host, origin.Host) {
		return ""
	}
	id := u.Query().Get("id")
	if id == "" {
		return ""
	}
	switch u.Path {
	case "/gtm.js":
		return "gtm.js?id=" + id
	case "/gtag/js":
		return "gtag/js?id=" + id
	}
	return ""
}

// gtmContainer is the part of a container's configuration that is read.
type gtmContainer struct {
	Resource struct {
		Macros []json.RawMessage `json:"macros"`
		Tags   []map[string]any  `json:"tags"`
		Rules  [][][]any         `json:"rules"`
	} `json:"resource"`
	Permissions map[string]struct {
		InjectScript struct {
			URLs []string `json:"urls"`
		} `json:"inject_script"`
	} `json:"permissions"`
}

var errNoGTMData = errors.New("no container data")

// readGTMContainer reads the configuration at the start of a container,
// reading no further than its end.
func readGTMContainer(r io.Reader) (*gtmContainer, error) {
	br := bufio.NewReaderSize(io.LimitReader(r, maxGTMBytes), 32<<10)
	// The configuration follows a copyright comment and a few lines.
	if !skipPast(br, "var data =", 4096) {
		return nil, errNoGTMData
	}
	var c gtmContainer
	if err := json.NewDecoder(br).Decode(&c); err != nil {
		return nil, err
	}
	return &c, nil
}

// skipPast reads r up to and including the first occurrence of marker, which
// must not repeat its first byte, within limit bytes.
func skipPast(r io.ByteReader, marker string, limit int) bool {
	matched := 0
	for range limit {
		c, err := r.ReadByte()
		if err != nil {
			return false
		}
		switch {
		case c == marker[matched]:
			matched++
		case c == marker[0]:
			matched = 1
		default:
			matched = 0
		}
		if matched == len(marker) {
			return true
		}
	}
	return false
}

// evidence returns what the live tags of c are matched by.
func (c *gtmContainer) evidence() *gtmEvidence {
	tags := c.Resource.Tags

	// A tag is live if a rule adds it, or a live tag sequences it before
	// or after itself, and it isn't paused.
	live := make([]bool, len(tags))
	var mark func(i int)
	mark = func(i int) {
		if i < 0 || i >= len(tags) || live[i] || tags[i] == nil {
			return
		}
		live[i] = true
		for _, key := range []string{"setup_tags", "teardown_tags"} {
			list, _ := tags[i][key].([]any)
			for _, item := range list {
				if ref, ok := item.([]any); ok && len(ref) >= 2 && ref[0] == "tag" {
					if n, ok := ref[1].(float64); ok {
						mark(int(n))
					}
				}
			}
		}
	}
	for _, rule := range c.Resource.Rules {
		for _, clause := range rule {
			if len(clause) == 0 || clause[0] != "add" {
				continue
			}
			for _, n := range clause[1:] {
				if n, ok := n.(float64); ok {
					mark(int(n))
				}
			}
		}
	}

	macros := make([]any, len(c.Resource.Macros))
	decoded := make([]bool, len(c.Resource.Macros))
	macro := func(n int) any {
		if n < 0 || n >= len(macros) {
			return nil
		}
		if !decoded[n] {
			decoded[n] = true
			json.Unmarshal(c.Resource.Macros[n], &macros[n])
		}
		return macros[n]
	}

	ev := &gtmEvidence{}
	var lines strings.Builder
	htmlSize := 0
	// written holds the lines written and the templates whose injected
	// scripts are listed.
	written := map[string]bool{}
	for i, tag := range tags {
		if !live[i] {
			continue
		}
		fn, _ := tag["function"].(string)
		if fn == "" || fn == "__paused" {
			continue
		}
		var line strings.Builder
		line.WriteString("gtm:tag ")
		line.WriteString(fn)
		line.WriteByte(' ')
		var ids []string
		collectGoogleIDs(tag, macro, 0, &ids)
		sort.Strings(ids)
		for _, id := range ids {
			line.WriteString("id:")
			line.WriteString(id)
			line.WriteByte(' ')
		}
		line.WriteByte('\n')
		// Containers repeat tags of a template (one per event or
		// conversion), so many lines are the same.
		if l := line.String(); !written[l] {
			written[l] = true
			lines.WriteString(l)
		}

		if !written[fn] {
			written[fn] = true
			for _, u := range c.Permissions[fn].InjectScript.URLs {
				if u = injectedScriptURL(u); u != "" {
					ev.scriptSrcs = append(ev.scriptSrcs, u)
				}
			}
		}

		if fn == "__html" && htmlSize < maxGTMHTML {
			markup := templateString(tag["vtp_html"])
			if len(markup) > maxGTMHTML-htmlSize {
				markup = markup[:maxGTMHTML-htmlSize]
			}
			htmlSize += len(markup)
			if markup != "" {
				ev.html = append(ev.html, markup)
				srcs, scripts := htmlScripts(markup)
				ev.scriptSrcs = append(ev.scriptSrcs, srcs...)
				ev.inlineScripts = append(ev.inlineScripts, scripts...)
			}
		}
	}
	ev.tags = lines.String()
	return ev
}

// collectGoogleIDs appends to ids the Google ids among the strings in v,
// following variable references (["macro", n]) depth levels deep.
func collectGoogleIDs(v any, macro func(int) any, depth int, ids *[]string) {
	if len(*ids) >= maxGTMIDs {
		return
	}
	switch v := v.(type) {
	case string:
		if isGoogleID(v) {
			for _, id := range *ids {
				if id == v {
					return
				}
			}
			*ids = append(*ids, v)
		}
	case []any:
		if len(v) == 2 && v[0] == "macro" {
			if n, ok := v[1].(float64); ok && depth < maxGTMDepth {
				collectGoogleIDs(macro(int(n)), macro, depth+1, ids)
			}
			return
		}
		for _, item := range v {
			collectGoogleIDs(item, macro, depth, ids)
		}
	case map[string]any:
		for key, item := range v {
			// The html of Custom HTML tags isn't settings.
			if key != "vtp_html" {
				collectGoogleIDs(item, macro, depth, ids)
			}
		}
	}
}

// isGoogleID reports whether s is a Google tag id: a GA4 measurement id
// (G-), a Universal Analytics property (UA-), a Google Ads (AW-) or Floodlight
// (DC-) account, or a Google tag (GT-).
func isGoogleID(s string) bool {
	prefix, rest, ok := strings.Cut(s, "-")
	if !ok || len(rest) < 4 || len(rest) > 20 {
		return false
	}
	switch prefix {
	case "G", "UA", "AW", "DC", "GT":
	default:
		return false
	}
	for i := 0; i < len(rest); i++ {
		if c := rest[i]; !isGTMIDChar(c) && c != '-' {
			return false
		}
	}
	return true
}

// templateString returns the text of a GTM value that is a string or a
// template (["template", "text", ["escape", ["macro", n], ...], "text"]),
// leaving out the variables.
func templateString(v any) string {
	switch v := v.(type) {
	case string:
		return v
	case []any:
		if len(v) == 0 || v[0] != "template" {
			return ""
		}
		var b strings.Builder
		for _, part := range v[1:] {
			if s, ok := part.(string); ok {
				b.WriteString(s)
			}
		}
		return b.String()
	}
	return ""
}

// injectedScriptURL returns the URL of an inject_script permission as a
// script src, or "" if it is a pattern for any host. A trailing wildcard,
// as in https://snap.licdn.com/*, is dropped.
func injectedScriptURL(u string) string {
	u = strings.TrimRight(u, "*")
	parsed, err := url.Parse(u)
	if err != nil || parsed.Host == "" || strings.Contains(parsed.Host, "*") {
		return ""
	}
	return u
}

// htmlScripts returns the srcs and the contents of the scripts in markup.
func htmlScripts(markup string) (srcs, scripts []string) {
	z := html.NewTokenizer(strings.NewReader(markup))
	inScript := false
	for {
		switch z.Next() {
		case html.ErrorToken:
			return srcs, scripts
		case html.StartTagToken:
			name, hasAttr := z.TagName()
			inScript = atom.Lookup(name) == atom.Script
			for hasAttr && inScript {
				var key, val []byte
				key, val, hasAttr = z.TagAttr()
				if string(key) == "src" {
					if src := strings.TrimSpace(string(val)); src != "" {
						srcs = append(srcs, src)
					}
				}
			}
		case html.TextToken:
			if inScript {
				if code := strings.TrimSpace(string(z.Text())); code != "" {
					scripts = append(scripts, code)
				}
			}
		case html.EndTagToken:
			inScript = false
		}
	}
}

// matchGTM matches the evidence of a container. Script srcs are resolved
// against base, the page URL, which may be nil.
func (s *Wappalyze) matchGTM(ev *gtmEvidence, base *url.URL) []matchPartResult {
	f := s.fingerprints
	var found []matchPartResult
	if ev.tags != "" {
		found = append(found, f.matchString(ev.tags, scriptPart, s.regexTimeout)...)
	}
	for _, src := range ev.scriptSrcs {
		if abs := resolveURL(base, src); abs != "" {
			src = abs
		}
		found = append(found, f.matchString(src, scriptSrcPart, s.regexTimeout)...)
	}
	if len(ev.html) > 0 {
		found = append(found, f.matchString(strings.ToLower(strings.Join(ev.html, "\n")), htmlPart, s.regexTimeout)...)
	}
	if len(ev.inlineScripts) > 0 {
		found = append(found, f.matchString(strings.Join(ev.inlineScripts, "\n"), scriptPart, s.regexTimeout)...)
	}
	for _, code := range ev.inlineScripts {
		found = append(found, f.matchJSGlobals(code, true)...)
	}
	// A container's tags describe what it loads, never how the site is
	// built or hosted: a template that may inject a helper from an S3
	// bucket or jsDelivr says nothing about the site's own infrastructure.
	kept := found[:0]
	for _, m := range found {
		if fp := f.lookup(m.application); fp == nil || !hasInfraCategory(fp.cats) {
			kept = append(kept, m)
		}
	}
	return kept
}

// gtmInfraCategories are categories of site infrastructure (CMS, servers,
// languages, databases, hosting, CDNs) that GTM evidence never reports.
var gtmInfraCategories = map[int]bool{
	1: true, 3: true, 9: true, 18: true, 22: true, 23: true, 27: true, 28: true,
	31: true, 33: true, 34: true, 57: true, 60: true, 62: true, 63: true,
	64: true, 65: true, 88: true,
}

func hasInfraCategory(cats []int) bool {
	for _, c := range cats {
		if gtmInfraCategories[c] {
			return true
		}
	}
	return false
}
