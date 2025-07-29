package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/kavinsood/kitsune/internal/profiler"
)

func main() {
	fmt.Println("Starting Kitsune API server...")

	// Initialize the profiler
	engine, err := profiler.New()
	if err != nil {
		log.Fatalf("Failed to initialize profiler engine: %v", err)
	}

	// Set up HTTP routes
	http.HandleFunc("/analyze", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
			return
		}

		targetURL := r.FormValue("url")
		if targetURL == "" {
			http.Error(w, "URL parameter is required", http.StatusBadRequest)
			return
		}

		// Make HTTP request to the target URL
		resp, err := http.Get(targetURL)
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

		// Perform fingerprinting with detailed info
		results := engine.FingerprintWithInfoAndURL(resp.Header, body, targetURL)

		// Create response struct
		type Technology struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Website     string `json:"website"`
		}
		
		type Response struct {
			Technologies []Technology `json:"technologies"`
		}
		
		// Populate the response
		response := Response{
			Technologies: make([]Technology, 0, len(results)),
		}
		
		for tech, info := range results {
			response.Technologies = append(response.Technologies, Technology{
				Name:        tech,
				Description: info.Description,
				Website:     info.Website,
			})
		}
		
		// Set content type and marshal to JSON
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, fmt.Sprintf("Error encoding response: %v", err), http.StatusInternalServerError)
			return
		}
	})

	// Start the server
	fmt.Println("Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}