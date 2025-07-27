package kitsune

import (
	"net/http"
	"reflect"
	"regexp"
	"testing"
)

// Helper to rebuild global patterns after adding test fingerprints
// func rebuildPatternsForTest(k *Kitsune) {
// 	k.patterns = buildGlobalPatterns(k.fingerprints.Apps)
// }

func TestContextAwareDetection(t *testing.T) {
	k, err := NewFromFile("testdata/fingerprints_context.json", false, false)
	if err != nil {
		t.Fatalf("failed to create Kitsune instance: %v", err)
	}

	html := `<!DOCTYPE html><html><head>
	<meta name="generator" content="WordPressOnly 6.0">
	<script src="externalscriptonly.js"></script>
	</head><body>
	<p>bodytextonly</p>
	<script>inlinescriptonly</script>
	</body></html>`
	headers := http.Header{}
	technologies, _ := k.Fingerprint(headers, []byte(html))

	if _, ok := technologies["TestTech"]; !ok {
		t.Errorf("Expected TestTech to be detected in context-aware HTML")
	}

	// Negative test: pattern should not match in wrong context
	htmlWrong := `<!DOCTYPE html><html><head>
	<meta name="generator" content="NotWordPress">
	<script src="not-externalscript.js"></script>
	</head><body>
	<p>notbodytext</p>
	<script>notinlinescript</script>
	</body></html>`
	headers = http.Header{}
	technologiesWrong, _ := k.Fingerprint(headers, []byte(htmlWrong))
	if _, ok := technologiesWrong["TestTech"]; ok {
		t.Errorf("Did not expect TestTech to be detected in wrong context")
	}
}

func mustCompile(expr string) *regexp.Regexp {
	r, err := regexp.Compile(expr)
	if err != nil {
		panic(err)
	}
	return r
}

func TestCategoryMapping(t *testing.T) {
	var errInit error
	categoryMap, errInit = loadCategories()
	if errInit != nil {
		t.Fatalf("failed to load categories: %v", errInit)
	}
	k, err := NewFromFile("testdata/fingerprints_category.json", false, false)
	if err != nil {
		t.Fatalf("failed to create Kitsune instance: %v", err)
	}
	ids := []int{1, 18, 52}
	names := GetCategoryNames(ids)
	if len(names) == 0 {
		t.Errorf("Expected non-empty category names for IDs %v", ids)
	}
	catMap := GetAllCategories()
	if len(catMap) == 0 {
		t.Errorf("Expected non-empty category map")
	}
	techs := map[string]Detection{"TestTech": {}}
	catsInfo := k.GetCategories(techs)
	if len(catsInfo) == 0 || !reflect.DeepEqual(catsInfo["TestTech"].Cats, ids) || len(catsInfo["TestTech"].Names) == 0 {
		t.Errorf("Expected correct CatsInfo for TestTech, got %+v", catsInfo["TestTech"])
	}
}

func TestCookieDetection(t *testing.T) {
	k, err := NewFromFile("testdata/fingerprints_cookie.json", false, false)
	if err != nil {
		t.Fatalf("failed to create Kitsune instance: %v", err)
	}

	headers := http.Header{}
	headers.Add("Set-Cookie", "sessionid=abc123; Path=/; HttpOnly")
	techs, _ := k.Fingerprint(headers, []byte("<html></html>"))
	if _, ok := techs["CookieTech"]; !ok {
		t.Errorf("Expected CookieTech to be detected via cookie")
	}

	// Negative: wrong value
	headers = http.Header{}
	headers.Add("Set-Cookie", "sessionid=wrong; Path=/; HttpOnly")
	techs, _ = k.Fingerprint(headers, []byte("<html></html>"))
	if _, ok := techs["CookieTech"]; ok {
		t.Errorf("Did not expect CookieTech to be detected with wrong cookie value")
	}

	// Multiple Set-Cookie headers
	headers = http.Header{}
	headers.Add("Set-Cookie", "foo=bar; Path=/")
	headers.Add("Set-Cookie", "sessionid=abc123; Path=/; Secure")
	techs, _ = k.Fingerprint(headers, []byte("<html></html>"))
	if _, ok := techs["CookieTech"]; !ok {
		t.Errorf("Expected CookieTech to be detected with multiple Set-Cookie headers")
	}

	// Case insensitivity
	headers = http.Header{}
	headers.Add("Set-Cookie", "SESSIONID=abc123; Path=/")
	techs, _ = k.Fingerprint(headers, []byte("<html></html>"))
	if _, ok := techs["CookieTech"]; !ok {
		t.Errorf("Expected CookieTech to be detected with case-insensitive Set-Cookie header and cookie name")
	}

	// Malformed cookie (should be ignored, not panic)
	headers = http.Header{}
	headers.Add("Set-Cookie", "notacookie")
	techs, _ = k.Fingerprint(headers, []byte("<html></html>"))
	// Should not detect
	if _, ok := techs["CookieTech"]; ok {
		t.Errorf("Did not expect CookieTech to be detected with malformed cookie")
	}
}

func TestNewFromFileMinimal(t *testing.T) {
	k, err := NewFromFile("testdata/fingerprints_minimal.json", false, false)
	if err != nil {
		t.Fatalf("failed to create Kitsune from file: %v", err)
	}
	if len(k.apps) != 1 {
		t.Errorf("expected 1 fingerprint, got %d", len(k.apps))
	}
	if _, ok := k.apps["TestApp"]; !ok {
		t.Errorf("expected TestApp fingerprint to be loaded")
	}
}

func TestScriptPatternRawHTML(t *testing.T) {
	k, err := NewFromFile("testdata/fingerprints_context.json", false, false)
	if err != nil {
		t.Fatalf("failed to create Kitsune instance: %v", err)
	}

	html := `<!DOCTYPE html><html><head></head><body>
	<!-- <script>inlinescriptonly</script> -->
	<script>inlinescriptonly</script>
	<script>var x = "notinlinescript"</script>
	<script>broken < / script > inlinescriptonly</script>
	</body></html>`
	headers := http.Header{}
	technologies, _ := k.Fingerprint(headers, []byte(html))

	t.Logf("Detected: %+v", technologies)

	if _, ok := technologies["TestTech"]; !ok {
		t.Errorf("Expected TestTech to be detected in raw HTML script context (including commented/malformed)")
	}

	// Negative: pattern should not match if script is not present
	htmlWrong := `<!DOCTYPE html><html><head></head><body>
	<script>notinlinescript</script>
	</body></html>`
	technologiesWrong, _ := k.Fingerprint(headers, []byte(htmlWrong))
	if _, ok := technologiesWrong["TestTech"]; ok {
		t.Errorf("Did not expect TestTech to be detected when script pattern is not present")
	}
}

func TestGenericSelectorRegex(t *testing.T) {
	// Test cases that should be rejected (generic selectors)
	genericSelectors := []string{
		"div",
		"span",
		"body > div",
		"header + main",
		"nav ~ footer",
		"custom-element",
		"div span",
		"body > div > span",
	}

	// Test cases that should be allowed (specific selectors)
	specificSelectors := []string{
		"div.class",
		"#main",
		"div[data-test]",
		"div[class=main]",
		"div.specific-class",
		"#header .nav",
		"div[data-test-id='main-app']",
		"div.class > span",
		"div:first-child",
		"div::before",
	}

	// Test generic selectors (should match the regex and be rejected)
	for _, selector := range genericSelectors {
		if !genericSelectorRegex.MatchString(selector) {
			t.Errorf("Generic selector '%s' should match the regex but doesn't", selector)
		}
	}

	// Test specific selectors (should NOT match the regex and be allowed)
	for _, selector := range specificSelectors {
		if genericSelectorRegex.MatchString(selector) {
			t.Errorf("Specific selector '%s' should NOT match the regex but does", selector)
		}
	}
}

func TestDOMConfidenceScoring(t *testing.T) {
	// Test cases for different confidence levels
	testCases := []struct {
		selector    string
		expected    ConfidenceLevel
		description string
	}{
		// Low confidence cases (basic selectors)
		{"div.class", ConfidenceLow, "Basic class selector"},
		{"span[data-test]", ConfidenceLow, "Basic attribute selector without value"},
		{"div > span", ConfidenceLow, "Basic combinator selector"},

		// Medium confidence cases (more specific selectors)
		{"#main", ConfidenceMedium, "ID selector"},
		{"div[data-test='value']", ConfidenceMedium, "Attribute selector with value"},
		{"div:first-child", ConfidenceMedium, "Pseudo-selector"},
		{"div::before", ConfidenceMedium, "Pseudo-element"},
		{"#header .nav", ConfidenceMedium, "ID with class"},
		{"div[data-test='value']:hover", ConfidenceMedium, "Attribute with pseudo-selector"},
		{"#main[data-test='value']", ConfidenceMedium, "ID with attribute value"},
	}

	for _, tc := range testCases {
		result := calculateDOMConfidence(tc.selector)
		if result != tc.expected {
			t.Errorf("Selector '%s' (%s): expected %v, got %v",
				tc.selector, tc.description, tc.expected, result)
		}
	}
}
