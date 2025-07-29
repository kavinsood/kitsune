package profiler

import (
	"bytes"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/html"
)

// streamingParseHTML parses HTML content and sends asset URLs to the fetcher as they are discovered
// It returns DOM-based technologies, meta tag technologies, and handles script src detection
// This is a streaming version of the previous parseBodyForDOMAnalysis and checkBody functions
func (s *Wappalyze) streamingParseHTML(body []byte, fetcher *AssetFetcher) ([]matchPartResult, *goquery.Document) {
	var technologies []matchPartResult
	
	// Parse the HTML document with goquery for DOM analysis
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		// Return a minimal result if parsing fails
		return technologies, nil
	}
	
	// Process script tags - stream URLs to the fetcher as we find them
	doc.Find("script[src]").Each(func(i int, elem *goquery.Selection) {
		if src, exists := elem.Attr("src"); exists && src != "" {
			// Send this script URL to the fetcher immediately
			fetcher.AddURL(src, "script", 5)
			
			// Also check for script src fingerprints
			scriptTech := s.fingerprints.matchString(src, scriptPart, s.regexTimeout)
			if len(scriptTech) > 0 {
				technologies = append(technologies, scriptTech...)
			}
		}
	})
	
	// Process stylesheet links - stream URLs to the fetcher as we find them
	doc.Find("link[rel=stylesheet][href]").Each(func(i int, elem *goquery.Selection) {
		if href, exists := elem.Attr("href"); exists && href != "" {
			// Send this stylesheet URL to the fetcher immediately
			fetcher.AddURL(href, "style", 3)
		}
	})
	
	// Process meta tags
	metaTech := s.analyzeMeta(doc)
	technologies = append(technologies, metaTech...)
	
	// Process DOM patterns
	domTech := s.analyzeDOM(doc)
	technologies = append(technologies, domTech...)
	
	// Also process the HTML body for raw pattern matching
	bodyString := strings.ToLower(string(body))
	htmlTech := s.fingerprints.matchString(bodyString, htmlPart, s.regexTimeout)
	technologies = append(technologies, htmlTech...)
	
	return technologies, doc
}

// extractTitleWithTokenizer extracts the page title using an HTML tokenizer
// This is a separate function for clarity and to allow title extraction 
// even when full HTML parsing fails
func (s *Wappalyze) extractTitleWithTokenizer(body []byte) string {
	var title string

	// Tokenize the HTML document and check for title tags
	tokenizer := html.NewTokenizer(bytes.NewReader(body))

	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			return title
		case html.StartTagToken:
			token := tokenizer.Token()
			if token.Data == "title" {
				// Next text token will be the actual title
				if tokenizer.Next() == html.TextToken {
					title = tokenizer.Token().Data
					return title
				}
			}
		}
	}
}