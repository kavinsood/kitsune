package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os" // Add this import
	"strings"

	"github.com/kavinsood/kitsune/kitsune"

	safeurl "github.com/doyensec/safeurl"
)

type Server struct {
	kitsuneClient  *kitsune.Kitsune
	ssrfHTTPClient kitsune.HTTPDoer
}

type CategoryResponse struct {
	Category     string   `json:"category"`
	Technologies []string `json:"technologies"`
}

type FingerprintResponse struct {
	URL          string             `json:"url"`
	Technologies []string           `json:"technologies"`
	Categories   []CategoryResponse `json:"categories"`
	Error        string             `json:"error,omitempty"`
}

func NewServer() (*Server, error) {
	cfg := safeurl.GetConfigBuilder().Build()
	ssrfClient := safeurl.Client(cfg)
	client, err := kitsune.New(ssrfClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create kitsune client: %w", err)
	}
	return &Server{kitsuneClient: client, ssrfHTTPClient: ssrfClient}, nil
}

// buildFingerprintResponse prepares the FingerprintResponse struct for a given request.
func (s *Server) buildFingerprintResponse(url string) FingerprintResponse {
	technologies, err := s.kitsuneClient.FingerprintURL(url)
	categories := s.kitsuneClient.GetCategories(technologies)

	// Build category-based output
	catToTechs := make(map[string][]string)
	for tech, catInfo := range categories {
		for _, catName := range catInfo.Names {
			catToTechs[catName] = append(catToTechs[catName], tech)
		}
	}
	var catResponses []CategoryResponse
	for cat, techs := range catToTechs {
		catResponses = append(catResponses, CategoryResponse{
			Category:     cat,
			Technologies: techs,
		})
	}

	// Extract just the technology names
	var techNames []string
	for tech := range technologies {
		techNames = append(techNames, tech)
	}

	response := FingerprintResponse{
		URL:          url,
		Technologies: techNames,
		Categories:   catResponses,
	}
	if err != nil {
		response.Error = err.Error()
		return response
	}
	return response
}

// writeJSONResponse writes any struct as JSON to the response writer.
func writeJSONResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (s *Server) analyzeAndRespond(w http.ResponseWriter, url string) {
	response := s.buildFingerprintResponse(url)
	writeJSONResponse(w, response)
}

func (s *Server) handleError(w http.ResponseWriter, err error, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func (s *Server) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	const maxBodySize = 5 * 1024 * 1024 // 5 MB
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	type analyzeRequest struct {
		URL string `json:"url"`
	}
	var req analyzeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.handleError(w, err, http.StatusBadRequest)
		return
	}
	if req.URL == "" {
		s.handleError(w, errors.New("URL is required"), http.StatusBadRequest)
		return
	}
	s.analyzeAndRespond(w, req.URL)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

// corsMiddleware wraps an http.Handler to enforce CORS policies.
func corsMiddleware(next http.Handler, allowedOrigins []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// Check if the origin is in our allowed list
		for _, allowedOrigin := range allowedOrigins {
			if origin == allowedOrigin {
				w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
				w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
				break
			}
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func main() {
	// --- Read configuration from environment ---
	allowedOriginsStr := os.Getenv("ALLOWED_ORIGINS")
	var allowedOrigins []string

	if allowedOriginsStr == "" {
		// Default to localhost for development
		allowedOrigins = []string{"http://localhost:3000"}
	} else {
		// Parse comma-separated list of origins
		allowedOrigins = strings.Split(allowedOriginsStr, ",")
		// Trim whitespace from each origin
		for i, origin := range allowedOrigins {
			allowedOrigins[i] = strings.TrimSpace(origin)
		}
	}

	server, err := NewServer()
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/analyze", server.handleAnalyze)
	mux.HandleFunc("/health", server.handleHealth)

	// Pass the configured origins to the middleware.
	handler := corsMiddleware(mux, allowedOrigins)

	// Use the PORT environment variable provided by Render.
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Hardcoded default for localhost development
	}

	log.Printf("Starting Kitsune server on port %s, allowing origins: %v", port, allowedOrigins)

	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatal(err)
	}
}
