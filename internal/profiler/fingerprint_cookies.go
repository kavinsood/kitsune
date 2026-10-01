package profiler

import (
	"net/http"
	"strings"
)

// cookieValues returns the cookies set by the Set-Cookie headers of
// headers (keyed by lowercased name), keyed by lowercased cookie name as
// wappalyzer keys them. Malformed cookies are skipped.
func cookieValues(headers map[string][]string) map[string][]string {
	cookies := make(map[string][]string)
	for _, line := range headers["set-cookie"] {
		for _, setCookie := range splitSetCookie(line) {
			cookie, err := http.ParseSetCookie(setCookie)
			if err != nil {
				continue
			}
			name := strings.ToLower(cookie.Name)
			cookies[name] = append(cookies[name], cookie.Value)
		}
	}
	return cookies
}

// splitSetCookie splits a Set-Cookie header value into the cookies it sets.
// It normally sets one, but the fetch API joins the Set-Cookie headers of a
// response with ", ", so a comma followed by name= starts another cookie,
// unless it is the comma of an Expires date ("Expires=Thu, 01 Jan ...").
func splitSetCookie(line string) []string {
	var out []string
	start := 0
	for i := 0; i < len(line); i++ {
		if line[i] != ',' {
			continue
		}
		attr := line[start:i]
		if semi := strings.LastIndexByte(attr, ';'); semi >= 0 {
			attr = attr[semi+1:]
		}
		attr = strings.TrimSpace(attr)
		if len(attr) >= 8 && strings.EqualFold(attr[:8], "expires=") && !strings.ContainsRune(attr, ' ') {
			continue // the comma after the weekday
		}
		next := strings.TrimLeft(line[i+1:], " ")
		eq := strings.IndexByte(next, '=')
		if eq <= 0 || strings.ContainsAny(next[:eq], ";, ") {
			continue
		}
		out = append(out, line[start:i])
		start = i + 1
	}
	return append(out, line[start:])
}
