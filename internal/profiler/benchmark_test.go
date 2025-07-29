package profiler

import (
	"io/ioutil"
	"net/http"
	"testing"
)

func BenchmarkFingerprint(b *testing.B) {
	html, err := ioutil.ReadFile("testdata/drupal.html")
	if err != nil {
		b.Skipf("Skipping benchmark: %v", err)
		return
	}

	headers := http.Header{
		"Server":        []string{"nginx/1.19.0"},
		"Content-Type":  []string{"text/html"},
		"X-Powered-By":  []string{"PHP/7.4.3"},
		"X-Drupal-Cache": []string{"HIT"},
	}

	wappalyzer, err := New()
	if err != nil {
		b.Fatal(err)
	}

	headersMap := make(map[string][]string)
	for k, v := range headers {
		headersMap[k] = v
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wappalyzer.Fingerprint(headersMap, html)
	}
}