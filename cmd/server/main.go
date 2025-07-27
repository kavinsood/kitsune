package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os" // Add this import

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

func main() {
	server, err := NewServer()
	if err != nil {
		log.Fatal(err)
	}

	// Set up routes
	http.HandleFunc("/analyze", server.handleAnalyze)
	http.HandleFunc("/health", server.handleHealth)

	// Use the PORT environment variable provided by Render
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Fallback for local development
	}

	log.Printf("Starting Kitsune server on port %s", port)

	// Listen on all interfaces with the correct port
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}
