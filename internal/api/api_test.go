package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kavinsood/kitsune/internal/profiler"
)

func TestBlockReason(t *testing.T) {
	isolation := `<!DOCTYPE html><html><head><meta name="referrer" content="no-referrer">` +
		`<script src="https://content.browser.run/7/bootstrap.abc.js"></script></head><body></body></html>`
	for _, tt := range []struct {
		name   string
		status int
		header http.Header
		body   string
		want   string
	}{
		{"ok", 200, http.Header{"Server": {"nginx"}}, "<html><title>Home</title></html>", ""},
		{"forbidden", 403, nil, "", "HTTP 403"},
		{"cloudflare", 200, nil, "<title>Just a moment...</title>", "bot challenge"},
		{"fastly challenge", 200, nil, "<html><head><title>Client Challenge</title></head></html>", "bot challenge"},
		{"marker in a big page", 200, nil, "<title>Client Challenge</title>" + strings.Repeat("x", 64<<10), ""},
		{"isolation header", 200, http.Header{"Cf-Biso-Version": {"1"}}, "<html></html>", reasonIsolation},
		{"isolation page", 200, nil, isolation, reasonIsolation},
		{"titled page using the isolation host", 200, nil, strings.Replace(isolation, "<head>", "<head><title>Docs</title>", 1), ""},
	} {
		if got := blockReason(tt.status, tt.header, []byte(tt.body)); got != tt.want {
			t.Errorf("%s: blockReason = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// TestAnalyzeResponses checks that a blocked response still
// reports the techs its headers show, and that the page is analyzed at the
// URL it was redirected to.
func TestAnalyzeResponses(t *testing.T) {
	old := profiler.DNSRecordTypes
	profiler.DNSRecordTypes = nil
	defer func() { profiler.DNSRecordTypes = old }()
	engine, err := profiler.New()
	if err != nil {
		t.Fatal(err)
	}
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/blocked":
			w.Header().Set("Server", "cloudflare")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("<title>Access Denied</title>"))
		case "/old":
			http.Redirect(w, r, "/new/", http.StatusFound)
		case "/new/":
			w.Header().Set("Server", "cloudflare")
			w.Write([]byte("<html><title>Home</title></html>"))
		}
	}))
	defer site.Close()
	api := httptest.NewServer(NewMux(engine))
	defer api.Close()

	analyze := func(path string, v any) {
		t.Helper()
		resp, err := http.Post(api.URL+"/analyze", "application/json", strings.NewReader(`{"url":"`+site.URL+path+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
			t.Fatal(err)
		}
	}
	hasTech := func(techs []ResponseTechnology, name string) bool {
		for _, tech := range techs {
			if tech.Name == name {
				return true
			}
		}
		return false
	}

	var blocked BlockedResponse
	analyze("/blocked", &blocked)
	if !blocked.Error || !blocked.Blocked || blocked.Status != 403 || !hasTech(blocked.Technologies, "Cloudflare") {
		t.Errorf("blocked response = %+v, want an error with Cloudflare detected", blocked)
	}

	var ok AnalyzeResponse
	analyze("/old", &ok)
	if ok.URL != site.URL+"/old" || ok.FinalURL != site.URL+"/new/" || !hasTech(ok.Technologies, "Cloudflare") {
		t.Errorf("response = %+v, want final URL %s/new/ with Cloudflare detected", ok, site.URL)
	}
}
