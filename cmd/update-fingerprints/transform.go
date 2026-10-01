package main

import (
	"strconv"
	"strings"
)

// cspHeaders are the headers listing the origins a page may load from.
var cspHeaders = []string{"content-security-policy", "content-security-policy-report-only"}

// downrankCSP caps the confidence of the patterns for CSP headers at conf.
//
// Many fingerprints detect a service by its origin in the CSP header, but
// an origin being allowed is no proof the service is used: sites copy
// policies around and allow more than they load. With the confidence
// capped, such a match needs corroboration from another signal once the
// engine sums confidences.
func downrankCSP(techs map[string]*Tech, conf int, stats counter) {
	for _, name := range sortedKeys(techs) {
		t := techs[name]
		for _, h := range cspHeaders {
			p, ok := t.Headers[h]
			if !ok || regexPart(p) == "" {
				continue
			}
			if c, ok := confidenceOf(p); ok && c <= conf {
				continue
			}
			t.Headers[h] = withConfidence(p, conf)
			stats["csp header patterns down-ranked"]++
		}
	}
}

// confidenceOf returns the confidence modifier of a pattern, if it has one.
func confidenceOf(pattern string) (int, bool) {
	for _, mod := range strings.Split(pattern, `\;`)[1:] {
		if v, ok := strings.CutPrefix(mod, "confidence:"); ok {
			n, err := strconv.Atoi(v)
			return n, err == nil
		}
	}
	return 0, false
}

// withConfidence returns pattern with its confidence modifier set to conf.
func withConfidence(pattern string, conf int) string {
	parts := strings.Split(pattern, `\;`)
	out := parts[:1]
	for _, mod := range parts[1:] {
		if !strings.HasPrefix(mod, "confidence:") {
			out = append(out, mod)
		}
	}
	out = append(out, "confidence:"+strconv.Itoa(conf))
	return strings.Join(out, `\;`)
}
