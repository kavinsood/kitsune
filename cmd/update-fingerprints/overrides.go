package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/andybalholm/cascadia"
)

// The overrides file, assets/overrides.json, is kitsune's own layer of
// fixes and additions, applied to the merged sources (before the RE2
// rewrites and the checks). It is an object with three optional members,
// applied in this order:
//
//	"remove": {tech: true | partial tech}
//	    true deletes the tech. A partial tech removes what it lists: the
//	    listed patterns of list fields (html, scriptSrc, ..., implies,
//	    requires, excludes) and the listed numbers of cats and
//	    requiresCategory; the listed keys of cookies, headers, js and probe
//	    (whatever their pattern); for meta and dns, the listed patterns of
//	    each key, or the key itself if its pattern is ""; and the listed dom
//	    selectors (whatever their checks).
//
//	"set": {tech: partial tech}
//	    Replaces what it lists: list fields, cats, requiresCategory and the
//	    description, website, icon and cpe as a whole; cookies, headers, js,
//	    meta, dns, probe and dom key by key (other keys are kept). The tech
//	    must exist.
//
//	"add": {tech: partial tech}
//	    Adds what it lists, as if the tech were in another source, ranked
//	    lowest: patterns are unioned (including requires and excludes,
//	    unlike between sources), and description, website, icon, cpe and
//	    cats are filled in if missing. Adding to a tech that doesn't exist
//	    creates it.
//
// Partial techs are in the Wappalyzer source format, so a pattern can be
// given as a string or a list, and dom as a selector, a list of selectors
// or {selector: checks}. Every member may have a "_comment", and so may
// the file. Patterns and selectors in "set" and "add" must be valid as
// they are (in RE2 and cascadia); the run fails otherwise. Removals that
// remove nothing are reported, as upstream may have fixed or changed the
// data.

type overridesFile struct {
	Comment any                        `json:"_comment"`
	Remove  map[string]json.RawMessage `json:"remove"`
	Set     map[string]json.RawMessage `json:"set"`
	Add     map[string]json.RawMessage `json:"add"`
}

// override is a partial tech of the overrides file.
type override struct {
	tech *Tech
	// fields are the fields present.
	fields map[string]bool
}

func parseOverride(data json.RawMessage, split bool) (*override, error) {
	var raw rawTech
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	n := &normalizer{stats: make(counter), split: split}
	t, err := n.normalize(&raw)
	if err != nil {
		return nil, err
	}
	o := &override{tech: t, fields: make(map[string]bool)}
	for k := range fields {
		o.fields[k] = true
	}
	return o, nil
}

// applyOverrides applies the overrides in file to techs. Problems that
// make an override invalid are returned as an error; overrides that do
// nothing are reported to l.
func applyOverrides(file string, techs map[string]*Tech, l *linter) (counter, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var ovr overridesFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ovr); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	stats := make(counter)

	for _, name := range sortedKeys(ovr.Remove) {
		raw := ovr.Remove[name]
		if string(bytes.TrimSpace(raw)) == "true" {
			if techs[name] == nil {
				l.add(sevWarn, "override-noop", name, "remove: tech doesn't exist")
			}
			delete(techs, name)
			stats["techs removed"]++
			continue
		}
		o, err := parseOverride(raw, false)
		if err != nil {
			return nil, fmt.Errorf("%s: remove %q: %w", file, name, err)
		}
		t := techs[name]
		if t == nil {
			l.add(sevWarn, "override-noop", name, "remove: tech doesn't exist")
			continue
		}
		for _, miss := range removeFrom(t, o.tech) {
			l.add(sevWarn, "override-noop", name, "remove: %s isn't there", miss)
		}
		stats["techs with patterns removed"]++
	}

	for _, name := range sortedKeys(ovr.Set) {
		o, err := parseOverride(ovr.Set[name], true)
		if err == nil {
			err = validateOverride(o.tech)
		}
		if err != nil {
			return nil, fmt.Errorf("%s: set %q: %w", file, name, err)
		}
		t := techs[name]
		if t == nil {
			return nil, fmt.Errorf("%s: set %q: no such tech (use add to create one)", file, name)
		}
		setFields(t, o)
		stats["techs with fields set"]++
	}

	for _, name := range sortedKeys(ovr.Add) {
		o, err := parseOverride(ovr.Add[name], true)
		if err == nil {
			err = validateOverride(o.tech)
		}
		if err != nil {
			return nil, fmt.Errorf("%s: add %q: %w", file, name, err)
		}
		t := techs[name]
		if t == nil {
			techs[name] = o.tech
			stats["techs created"]++
			continue
		}
		for _, conflict := range addTo(t, o.tech) {
			return nil, fmt.Errorf("%s: add %q: %s", file, name, conflict)
		}
		stats["techs with patterns added"]++
	}
	return stats, nil
}

// validateOverride checks that the patterns and selectors of t are valid
// as they are.
func validateOverride(t *Tech) error {
	var err error
	mapPatterns(cloneTech(t), func(where, pattern string) (string, bool) {
		if _, e := compileRegex(regexPart(pattern)); e != nil && err == nil {
			err = fmt.Errorf("%s: %q: %v", where, pattern, e)
		}
		return pattern, true
	})
	for _, sel := range sortedKeys(t.DOM) {
		if _, e := cascadia.Compile(sel); e != nil && err == nil {
			err = fmt.Errorf("dom: %q: %v", sel, e)
		}
	}
	return err
}

// removeFrom removes from t what r lists, returning what it lists that t
// lacks.
func removeFrom(t, r *Tech) []string {
	var missing []string
	removeList := func(field string, l *[]string, drop []string) {
		for _, d := range drop {
			found := false
			out := (*l)[:0]
			for _, s := range *l {
				if s == d {
					found = true
				} else {
					out = append(out, s)
				}
			}
			*l = out
			if !found {
				missing = append(missing, fmt.Sprintf("%s %q", field, d))
			}
		}
		if len(*l) == 0 {
			*l = nil
		}
	}
	for _, f := range append(append([]listField(nil), listFields...), gateFields...) {
		removeList(f.name, f.get(t), *f.get(r))
	}
	removeInts := func(field string, l *[]int, drop []int) {
		for _, d := range drop {
			found := false
			out := (*l)[:0]
			for _, n := range *l {
				if n == d {
					found = true
				} else {
					out = append(out, n)
				}
			}
			*l = out
			if !found {
				missing = append(missing, fmt.Sprintf("%s %d", field, d))
			}
		}
	}
	removeInts("cats", &t.Cats, r.Cats)
	removeInts("requiresCategory", &t.RequiresCategory, r.RequiresCategory)

	for _, f := range keyedFields {
		m := *f.get(t)
		for _, k := range sortedKeys(*f.get(r)) {
			if _, ok := m[k]; !ok {
				missing = append(missing, fmt.Sprintf("%s[%s]", f.name, k))
			}
			delete(m, k)
		}
	}
	for _, k := range sortedKeys(r.Probe) {
		if _, ok := t.Probe[k]; !ok {
			missing = append(missing, fmt.Sprintf("probe[%s]", k))
		}
		delete(t.Probe, k)
	}
	for _, f := range multiKeyedFields {
		m := *f.get(t)
		for _, k := range sortedKeys(*f.get(r)) {
			cur, ok := m[k]
			if !ok {
				missing = append(missing, fmt.Sprintf("%s[%s]", f.name, k))
				continue
			}
			drop := (*f.get(r))[k]
			if len(drop) == 0 {
				delete(m, k)
				continue
			}
			removeList(f.name+"["+k+"]", &cur, drop)
			if len(cur) == 0 {
				// Removing every pattern mustn't leave an existence check.
				delete(m, k)
			} else {
				m[k] = cur
			}
		}
	}
	for _, sel := range sortedKeys(r.DOM) {
		if _, ok := t.DOM[sel]; ok {
			delete(t.DOM, sel)
			continue
		}
		// The selector list may have been split (see normalizeDOM).
		parts := splitSelector(sel)
		found := len(parts) > 1
		for _, p := range parts {
			if _, ok := t.DOM[p]; !ok {
				found = false
			}
		}
		if !found {
			missing = append(missing, fmt.Sprintf("dom %q", sel))
			continue
		}
		for _, p := range parts {
			delete(t.DOM, p)
		}
	}
	return missing
}

// setFields replaces the fields of t that o lists.
func setFields(t *Tech, o *override) {
	s := o.tech
	for _, f := range append(append([]listField(nil), listFields...), gateFields...) {
		if o.fields[f.name] {
			*f.get(t) = *f.get(s)
		}
	}
	if o.fields["cats"] {
		t.Cats = s.Cats
	}
	if o.fields["requiresCategory"] {
		t.RequiresCategory = s.RequiresCategory
	}
	for _, f := range []struct {
		name string
		dst  *string
		src  string
	}{{"description", &t.Description, s.Description}, {"website", &t.Website, s.Website}, {"icon", &t.Icon, s.Icon}, {"cpe", &t.CPE, s.CPE}} {
		if o.fields[f.name] {
			*f.dst = f.src
		}
	}
	for _, f := range keyedFields {
		for k, v := range *f.get(s) {
			if *f.get(t) == nil {
				*f.get(t) = make(map[string]string)
			}
			(*f.get(t))[k] = v
		}
	}
	for k, v := range s.Probe {
		if t.Probe == nil {
			t.Probe = make(map[string]string)
		}
		t.Probe[k] = v
	}
	for _, f := range multiKeyedFields {
		for k, v := range *f.get(s) {
			if *f.get(t) == nil {
				*f.get(t) = make(map[string][]string)
			}
			(*f.get(t))[k] = v
		}
	}
	for sel, c := range s.DOM {
		if t.DOM == nil {
			t.DOM = make(map[string]*DOMCheck)
		}
		t.DOM[sel] = c
	}
}

// addTo adds a's patterns to t. It returns the patterns it couldn't add:
// those for a key of cookies, headers or js that already has a pattern
// with \; modifiers.
func addTo(t, a *Tech) []string {
	stats := make(counter)
	requires, excludes, requiresCategory := t.Requires, t.Excludes, t.RequiresCategory
	var conflicts []string
	for _, f := range keyedFields {
		for k, v := range *f.get(a) {
			cur, ok := (*f.get(t))[k]
			if ok && cur != "" && v != "" && cur != v && combinePatterns(cur, v, f.name, stats) == cur {
				conflicts = append(conflicts, fmt.Sprintf("%s[%s]: can't add %q to %q, which has modifiers; use set", f.name, k, v, cur))
			}
		}
	}
	if len(conflicts) > 0 {
		return conflicts
	}
	mergeTech(t, a, stats)
	t.Requires = sortedSet(union(requires, a.Requires))
	t.Excludes = sortedSet(union(excludes, a.Excludes))
	t.RequiresCategory = unionInts(requiresCategory, a.RequiresCategory)
	return nil
}
