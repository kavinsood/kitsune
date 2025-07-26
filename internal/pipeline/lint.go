package pipeline

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Lint validates all regex patterns in the normalized data.
func Lint(normalizedData []byte) error {
	var fps Fingerprints
	if err := json.Unmarshal(normalizedData, &fps); err != nil {
		return fmt.Errorf("failed to parse normalized data: %w", err)
	}

	var errs []string

	for app, fp := range fps.Apps {
		// CSS
		for _, pat := range fp.CSS {
			if err := lintPattern(app, "css", pat.Regex); err != nil {
				errs = append(errs, err.Error())
			}
		}
		// HTML
		for _, pat := range fp.HTML {
			if err := lintPattern(app, "html", pat.Regex); err != nil {
				errs = append(errs, err.Error())
			}
		}
		// Scripts
		for _, pat := range fp.Script {
			if err := lintPattern(app, "scripts", pat.Regex); err != nil {
				errs = append(errs, err.Error())
			}
		}
		// ScriptSrc
		for _, pat := range fp.ScriptSrc {
			if err := lintPattern(app, "scriptSrc", pat.Regex); err != nil {
				errs = append(errs, err.Error())
			}
		}
		// Cookies
		for k, pat := range fp.Cookies {
			if err := lintPattern(app, "cookies["+k+"]", pat.Regex); err != nil {
				errs = append(errs, err.Error())
			}
		}
		// JS
		for k, pat := range fp.JS {
			if err := lintPattern(app, "js["+k+"]", pat.Regex); err != nil {
				errs = append(errs, err.Error())
			}
		}
		// Headers
		for k, pat := range fp.Headers {
			if err := lintPattern(app, "headers["+k+"]", pat.Regex); err != nil {
				errs = append(errs, err.Error())
			}
		}
		// Meta
		for k, pats := range fp.Meta {
			for _, pat := range pats {
				if err := lintPattern(app, "meta["+k+"]", pat.Regex); err != nil {
					errs = append(errs, err.Error())
				}
			}
		}
		// URL
		for _, pat := range fp.URL {
			if err := lintPattern(app, "url", pat.Regex); err != nil {
				errs = append(errs, err.Error())
			}
		}
		// Robots
		for _, pat := range fp.Robots {
			if err := lintPattern(app, "robots", pat.Regex); err != nil {
				errs = append(errs, err.Error())
			}
		}
		// DOM
		for _, pat := range fp.DOM {
			if err := lintPattern(app, "dom", pat.Regex); err != nil {
				errs = append(errs, err.Error())
			}
		}
		// DNS
		for k, pat := range fp.DNS {
			if err := lintPattern(app, "dns["+k+"]", pat.Regex); err != nil {
				errs = append(errs, err.Error())
			}
		}
		// CertIssuer
		for k, pat := range fp.CertIssuer {
			if err := lintPattern(app, "certIssuer["+k+"]", pat.Regex); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}
	if len(errs) > 0 {
		for _, e := range errs {
			fmt.Println(e)
		}
		return fmt.Errorf("%d invalid regex patterns found:\n%s", len(errs), strings.Join(errs, "\n"))
	}
	return nil
}

func lintPattern(app, field, regexStr string) error {
	// Compile with case-insensitivity, matching runtime logic
	_, err := regexp.Compile("(?i)" + regexStr)
	if err != nil {
		return fmt.Errorf("invalid regex for app %s, field %s: %v", app, field, err)
	}
	return nil
}
