package profiler

import (
	"strconv"
	"strings"
)

// Resolving matches into detections, following wappalyzer's resolve: the
// confidence of a tech is the sum of the confidences of the distinct
// patterns that matched it, capped at 100, and its version the longest
// valid one found. Then excluded techs are removed and implied ones added.
// Techs gated by requires or requiresCategory only count if what they
// require is detected.
//
// Only techs whose confidence reaches 100 are reported (see
// reportedConfidence): a pattern with a lower confidence, like those for
// Content-Security-Policy headers, needs corroboration.

// reportedConfidence is the confidence a tech needs to be reported.
const reportedConfidence = 100

// maxResolveRounds bounds the rounds of gating in resolve. Excludes can
// remove what a gated tech requires, so the rounds needn't converge.
const maxResolveRounds = 8

// matchPartResult is a match of a pattern for a tech.
type matchPartResult struct {
	application string
	confidence  int
	version     string
	// evidence identifies what matched: matches of a tech with the same
	// evidence count once toward its confidence.
	evidence evidence
}

// evidence identifies the evidence for a match. For a pattern it is the
// pattern's content, so that identical patterns, which may or may not be
// shared, count once (as wappalyzer counts a regex once).
type evidence struct {
	src, version string
	confidence   int
	skipRegex    bool
}

// newMatch returns the match of pattern for app with the given version.
func newMatch(app string, pattern *ParsedPattern, version string) matchPartResult {
	return matchPartResult{
		application: app,
		confidence:  pattern.Confidence,
		version:     version,
		evidence:    evidence{src: pattern.src, version: pattern.Version, confidence: pattern.Confidence, skipRegex: pattern.SkipRegex},
	}
}

// detection is a resolved detection of a tech.
type detection struct {
	confidence int
	version    string
}

// reported reports whether d is confident enough to be reported.
func (d detection) reported() bool {
	return d.confidence >= reportedConfidence
}

// resolve resolves matches into detections, by tech name. It returns the
// techs with any confidence; callers report those for which reported is
// true. Techs not in f are dropped.
func (f *CompiledFingerprints) resolve(matches []matchPartResult) map[string]detection {
	type key struct {
		app      string
		evidence evidence
	}
	seen := make(map[key]bool, len(matches))
	detected := make(map[string]detection)
	for _, m := range matches {
		d := detected[m.application]
		if k := (key{m.application, m.evidence}); !seen[k] {
			seen[k] = true
			d.confidence = min(100, d.confidence+m.confidence)
		}
		d.version = betterVersion(d.version, m.version)
		detected[m.application] = d
	}

	// A gated tech counts if what it requires was reported in the previous
	// round, so iterate until the reported techs don't change.
	var resolved map[string]detection
	for round := 0; round < maxResolveRounds; round++ {
		next := make(map[string]detection, len(detected))
		for app, d := range detected {
			fp := f.lookup(app)
			if fp == nil || !f.requirementsMet(fp, resolved) {
				continue
			}
			next[app] = d
		}
		f.applyExcludes(next)
		f.applyImplies(next)
		if round > 0 && sameReported(next, resolved) {
			return next
		}
		resolved = next
	}
	return resolved
}

// requirementsMet reports whether the requires and requiresCategory of fp,
// if any, are met by the reported techs of resolved. As in wappalyzer, one
// required tech or category is enough.
func (f *CompiledFingerprints) requirementsMet(fp *CompiledFingerprint, resolved map[string]detection) bool {
	if len(fp.requires) == 0 && len(fp.requiresCategory) == 0 {
		return true
	}
	for _, name := range fp.requires {
		if resolved[name].reported() {
			return true
		}
	}
	if len(fp.requiresCategory) == 0 {
		return false
	}
	for app, d := range resolved {
		if !d.reported() {
			continue
		}
		if other := f.lookup(app); other != nil {
			for _, cat := range other.cats {
				for _, required := range fp.requiresCategory {
					if cat == required {
						return true
					}
				}
			}
		}
	}
	return false
}

// applyExcludes removes the techs excluded by the reported techs of
// resolved. Unlike wappalyzer, which reports techs of any confidence, a
// tech too uncertain to be reported doesn't exclude others.
func (f *CompiledFingerprints) applyExcludes(resolved map[string]detection) {
	var excluded []string
	for app, d := range resolved {
		if !d.reported() {
			continue
		}
		if fp := f.lookup(app); fp != nil {
			excluded = append(excluded, fp.excludes...)
		}
	}
	for _, name := range excluded {
		delete(resolved, name)
	}
}

// applyImplies adds the techs implied by those of resolved, recursively.
// An implied tech gets the lower of the confidence of the tech implying it
// and the confidence of the implication, and the version of the
// implication if any. Unlike wappalyzer, which only adds implied techs
// that aren't detected yet, an implication also raises the confidence of a
// detected tech, as only techs at 100 are reported.
func (f *CompiledFingerprints) applyImplies(resolved map[string]detection) {
	for changed := true; changed; {
		changed = false
		for app, d := range resolved {
			fp := f.lookup(app)
			if fp == nil {
				continue
			}
			for _, raw := range fp.implies {
				name, confidence, version, ok := parseImplied(raw)
				if !ok || f.lookup(name) == nil {
					continue
				}
				confidence = min(confidence, d.confidence)
				implied, exists := resolved[name]
				if exists && implied.confidence >= confidence && (implied.version != "" || version == "") {
					continue
				}
				implied.confidence = max(implied.confidence, confidence)
				if implied.version == "" {
					implied.version = version
				}
				resolved[name] = implied
				changed = true
			}
		}
	}
}

// sameReported reports whether a and b report the same techs.
func sameReported(a, b map[string]detection) bool {
	count := 0
	for app, d := range a {
		if d.reported() {
			if !b[app].reported() {
				return false
			}
			count++
		}
	}
	for _, d := range b {
		if d.reported() {
			count--
		}
	}
	return count == 0
}

// parseImplied parses an implies entry: a tech name with optional
// confidence and version modifiers, like "PHP\;confidence:50". It reports
// false if a modifier is invalid, so that the implication is dropped rather
// than made stronger than intended.
func parseImplied(raw string) (name string, confidence int, version string, ok bool) {
	name, modifiers, _ := strings.Cut(raw, "\\;")
	name = strings.TrimSpace(name)
	confidence = 100
	for modifiers != "" {
		var modifier string
		modifier, modifiers, _ = strings.Cut(modifiers, "\\;")
		k, v, found := strings.Cut(modifier, ":")
		if !found {
			continue
		}
		switch k {
		case "confidence":
			c, err := strconv.Atoi(v)
			if err != nil || c < 0 {
				return "", 0, "", false
			}
			confidence = c
		case "version":
			version = normalizeVersion(v)
		}
	}
	return name, confidence, version, name != ""
}

// maxVersionLen is the length of the longest version reported, as in
// wappalyzer.
const maxVersionLen = 15

// normalizeVersion returns version trimmed, or "" if it isn't a plausible
// version: wappalyzer only accepts letters, digits, '.', '_' and '-'.
func normalizeVersion(version string) string {
	version = strings.TrimSpace(version)
	for i := 0; i < len(version); i++ {
		c := version[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '.' || c == '_' || c == '-') {
			return ""
		}
	}
	return version
}

// betterVersion returns the better of the versions current and found, as
// wappalyzer chooses: the longest valid version of at most maxVersionLen
// characters, ignoring numbers of 10000 and over, which are likely to be
// timestamps.
func betterVersion(current, found string) string {
	found = normalizeVersion(found)
	if len(found) <= len(current) || len(found) > maxVersionLen {
		return current
	}
	if leadingInt(found) >= 10000 {
		return current
	}
	return found
}

// leadingInt returns the value of the leading digits of s, like JavaScript's
// parseInt, or 0 if there are none. It stops counting at 10000.
func leadingInt(s string) int {
	n := 0
	for i := 0; i < len(s) && '0' <= s[i] && s[i] <= '9'; i++ {
		n = n*10 + int(s[i]-'0')
		if n >= 10000 {
			return n
		}
	}
	return n
}
