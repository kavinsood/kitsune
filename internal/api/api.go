// Package api implements the Kitsune HTTP API, shared by the standalone server
// and the Cloudflare Worker build.
package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"runtime"
	"sort"
	"time"

	"github.com/kavinsood/kitsune/internal/profiler"
)

type AnalyzeRequest struct {
	URL string `json:"url"`
}

// Matches the frontend's Technology type
type ResponseTechnology struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Website     string `json:"website"`
}

// A new struct for a category and its technologies
type ResponseCategory struct {
	Category     string               `json:"category"`
	Technologies []ResponseTechnology `json:"technologies"`
}

// The final response payload
type AnalyzeResponse struct {
	URL string `json:"url"`
	// FinalURL is the URL the page was served from after redirects, if
	// that is not URL.
	FinalURL     string               `json:"final_url,omitempty"`
	Technologies []ResponseTechnology `json:"technologies"` // A flat list for the "All" view
	Categories   []ResponseCategory   `json:"categories"`   // The grouped list
}

// BlockedResponse is the payload for a site that blocked the scanner. The
// technologies are only those its response headers and cookies show.
type BlockedResponse struct {
	Error   bool   `json:"error"`
	Blocked bool   `json:"blocked"`
	Status  int    `json:"status"`
	Message string `json:"message"`
	AnalyzeResponse
}

// Metrics is logged as one JSON line per request so tail consumers can parse it.
type Metrics struct {
	Event       string `json:"event"`
	URL         string `json:"url"`
	FetchMs     int64  `json:"fetch_ms"`
	AnalyzeMs   int64  `json:"analyze_ms"`
	TotalMs     int64  `json:"total_ms"`
	Status      int    `json:"status"`
	Server      string `json:"server,omitempty"`
	BodyBytes   int    `json:"body_bytes"`
	BodyPrefix  string `json:"body_prefix,omitempty"`
	Techs       int    `json:"techs"`
	HeapAllocMB uint64 `json:"heap_alloc_mb"`
	HeapSysMB   uint64 `json:"heap_sys_mb"`
	SysMB       uint64 `json:"sys_mb"`
	NumGC       uint32 `json:"num_gc"`
	Requests    int64  `json:"isolate_requests"`
}

var requests int64

// PageClient fetches the page being analyzed. The Worker build replaces it
// with one that bypasses the fetch API; see cmd/kitsune-worker/egress.go.
var PageClient = http.DefaultClient

// userAgent matches the one the profiler's asset fetcher uses.
const userAgent = "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5931.0 Safari/537.36"

// NewMux returns the API routes backed by engine.
func NewMux(engine *profiler.Wappalyze) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	mux.HandleFunc("/analyze", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		requests++

		if r.Method != "POST" {
			http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
			return
		}

		var reqData AnalyzeRequest
		// Decode the JSON body instead of using FormValue
		if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}

		targetURL := reqData.URL // Get URL from the decoded struct
		if targetURL == "" {
			http.Error(w, "URL parameter is required", http.StatusBadRequest)
			return
		}

		// Make HTTP request to the target URL. Set a User-Agent explicitly: the
		// Workers fetch API sends none, and many sites reject such requests.
		req, err := http.NewRequestWithContext(r.Context(), "GET", targetURL, nil)
		if err != nil {
			http.Error(w, fmt.Sprintf("Invalid URL: %v", err), http.StatusBadRequest)
			return
		}
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		resp, err := PageClient.Do(req)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error fetching URL: %v", err), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		// Read body with size limit
		const maxBodySize = 5 * 1024 * 1024 // 5 MB
		limitedReader := io.LimitReader(resp.Body, maxBodySize)
		body, err := io.ReadAll(limitedReader)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error reading response body: %v", err), http.StatusInternalServerError)
			return
		}
		fetched := time.Now()

		// Analyze the page at the URL it was served from: relative script
		// and stylesheet URLs resolve against it, and url patterns match it.
		pageURL := targetURL
		if resp.Request != nil && resp.Request.URL != nil {
			pageURL = resp.Request.URL.String()
		}

		if reason := blockReason(resp.StatusCode, resp.Header, body); reason != "" {
			log.Printf(`{"event":"blocked","url":%q,"status":%d,"server":%q,"reason":%q}`, targetURL, resp.StatusCode, resp.Header.Get("Server"), reason)
			// The block page isn't the site, but its headers and cookies
			// usually still come from the site's stack (its CDN, say).
			// Those of an isolation page come from the isolation service.
			var results map[string]profiler.AppInfo
			if reason != reasonIsolation {
				results = engine.FingerprintWithInfoAndURL(resp.Header, nil, pageURL)
			}
			blocked := BlockedResponse{
				Error:           true,
				Blocked:         true,
				Status:          resp.StatusCode,
				Message:         fmt.Sprintf("This site blocked our scanner (%s), so we couldn't analyze it.", reason),
				AnalyzeResponse: newAnalyzeResponse(targetURL, pageURL, results),
			}
			// The frontend renders {error, message} responses as an error.
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(blocked)
			return
		}

		results := engine.FingerprintWithInfoAndURL(resp.Header, body, pageURL)
		analyzed := time.Now()
		response := newAnalyzeResponse(targetURL, pageURL, results)

		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		metrics := Metrics{
			Event:       "analyze",
			URL:         targetURL,
			FetchMs:     fetched.Sub(start).Milliseconds(),
			AnalyzeMs:   analyzed.Sub(fetched).Milliseconds(),
			TotalMs:     time.Since(start).Milliseconds(),
			Status:      resp.StatusCode,
			Server:      resp.Header.Get("Server"),
			BodyBytes:   len(body),
			Techs:       len(response.Technologies),
			HeapAllocMB: m.HeapAlloc >> 20,
			HeapSysMB:   m.HeapSys >> 20,
			SysMB:       m.Sys >> 20,
			NumGC:       m.NumGC,
			Requests:    requests,
		}
		if len(body) < 1024 {
			// Tiny bodies are usually block pages; keep a sample for debugging.
			metrics.BodyPrefix = string(body[:min(len(body), 160)])
		}
		if line, err := json.Marshal(metrics); err == nil {
			log.Println(string(line))
		}

		// Set content type and marshal to JSON
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Server-Timing", fmt.Sprintf("fetch;dur=%d, analyze;dur=%d", metrics.FetchMs, metrics.AnalyzeMs))
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, fmt.Sprintf("Error encoding response: %v", err), http.StatusInternalServerError)
			return
		}
	})

	return mux
}

// newAnalyzeResponse returns the response for the techs detected on the
// page at targetURL, served from pageURL.
func newAnalyzeResponse(targetURL, pageURL string, results map[string]profiler.AppInfo) AnalyzeResponse {
	allTechs := make([]ResponseTechnology, 0, len(results))
	categoriesMap := make(map[string][]ResponseTechnology)
	for techName, info := range results {
		tech := ResponseTechnology{
			Name:        techName,
			Description: info.Description,
			Website:     info.Website,
		}
		allTechs = append(allTechs, tech)

		if len(info.Categories) > 0 {
			for _, catName := range info.Categories {
				categoriesMap[catName] = append(categoriesMap[catName], tech)
			}
		} else {
			// Group tech without categories into a default one
			categoriesMap["Miscellaneous"] = append(categoriesMap["Miscellaneous"], tech)
		}
	}
	sort.Slice(allTechs, func(i, j int) bool { return allTechs[i].Name < allTechs[j].Name })

	categoryList := make([]ResponseCategory, 0, len(categoriesMap))
	for catName, techs := range categoriesMap {
		sort.Slice(techs, func(i, j int) bool { return techs[i].Name < techs[j].Name })
		categoryList = append(categoryList, ResponseCategory{
			Category:     catName,
			Technologies: techs,
		})
	}
	sort.Slice(categoryList, func(i, j int) bool {
		return categoryList[i].Category < categoryList[j].Category
	})

	response := AnalyzeResponse{
		URL:          targetURL,
		Technologies: allTechs,
		Categories:   categoryList,
	}
	if pageURL != targetURL {
		response.FinalURL = pageURL
	}
	return response
}

// challengeMarkers identify bot-challenge pages served in place of the site.
var challengeMarkers = []string{
	"<title>Just a moment...</title>", // Cloudflare
	"cf-browser-verification",
	"_Incapsula_Resource",
	"captcha-delivery.com",         // DataDome
	"px-captcha",                   // PerimeterX
	"<title>Access Denied</title>", // Akamai
	// Fastly's bot challenge (seen on drupal.org), served with status 200.
	"<title>Client Challenge</title>",
}

// reasonIsolation is the block reason for a browser isolation page.
const reasonIsolation = "browser isolation"

// blockReason reports why a response looks like a block rather than the
// site itself, or "" if it doesn't.
func blockReason(status int, header http.Header, body []byte) string {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusProxyAuthRequired,
		419, http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return fmt.Sprintf("HTTP %d", status)
	}
	// Cloudflare Browser Isolation serves its own page in place of the
	// site's, marked with this header, which loads the isolated site with
	// scripts from content.browser.run.
	if header.Get("Cf-Biso-Version") != "" || isolationPage(body) {
		return reasonIsolation
	}
	// Challenge pages are small; don't scan real pages that happen to
	// mention a marker.
	if len(body) < 64<<10 {
		for _, m := range challengeMarkers {
			if bytes.Contains(body, []byte(m)) {
				return "bot challenge"
			}
		}
	}
	return ""
}

// isolationPage reports whether body is a Cloudflare Browser Isolation
// interstitial: an untitled page loading scripts from content.browser.run.
func isolationPage(body []byte) bool {
	return len(body) < 64<<10 &&
		bytes.Contains(body, []byte("://content.browser.run/")) &&
		!bytes.Contains(bytes.ToLower(body), []byte("<title"))
}
