package profiler

import (
	"bytes"
	"unsafe"

	"golang.org/x/net/html"
)

// extractTitleFromTokenizer extracts the title from the HTML document using tokenizer
func (s *Wappalyze) extractTitleFromTokenizer(body []byte) string {
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
			switch token.Data {
			case "title":
				// Next text token will be the actual title of the page
				if tokenType := tokenizer.Next(); tokenType != html.TextToken {
					continue
				}
				title = tokenizer.Token().Data
			}
		}
	}
}

func (s *Wappalyze) getTitle(body []byte) string {
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
			switch token.Data {
			case "title":
				// Next text token will be the actual title of the page
				if tokenType := tokenizer.Next(); tokenType != html.TextToken {
					continue
				}
				title = tokenizer.Token().Data
			}
		}
	}
}

// getMetaNameAndContent gets name and content attributes from meta html token
func getMetaNameAndContent(token html.Token) (string, string, bool) {
	if len(token.Attr) < keyValuePairLength {
		return "", "", false
	}

	var name, content string
	for _, attr := range token.Attr {
		switch attr.Key {
		case "name":
			name = attr.Val
		case "content":
			content = attr.Val
		}
	}
	return name, content, true
}

// getScriptSource gets src tag from a script tag
func getScriptSource(token html.Token) (string, bool) {
	if len(token.Attr) < 1 {
		return "", false
	}

	var source string
	for _, attr := range token.Attr {
		switch attr.Key {
		case "src":
			source = attr.Val
		}
	}
	return source, true
}

// unsafeToString converts a byte slice to string and does it with
// zero allocations.
//
// NOTE: This function should only be used if its certain that the underlying
// array has not been manipulated.
//
// Reference - https://github.com/golang/go/issues/25484
func unsafeToString(data []byte) string {
	return *(*string)(unsafe.Pointer(&data))
}
