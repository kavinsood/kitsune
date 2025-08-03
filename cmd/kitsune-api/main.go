package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"

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
	URL          string               `json:"url"`
	Technologies []ResponseTechnology `json:"technologies"` // A flat list for the "All" view
	Categories   []ResponseCategory   `json:"categories"`   // The grouped list
}

func main() {
	fmt.Println("Starting Kitsune API server...")

	// Get port from environment variable (for Render) or default to 8080
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Construct the listen address with "0.0.0.0" to accept external connections
	listenAddr := "0.0.0.0:" + port

	// Initialize the profiler
	engine, err := profiler.New()
	if err != nil {
		log.Fatalf("Failed to initialize profiler engine: %v", err)
	}

	// Set up HTTP routes
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	http.HandleFunc("/analyze", func(w http.ResponseWriter, r *http.Request) {
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

		// Data structures to build the response
		allTechs := make([]ResponseTechnology, 0, len(results))
		categoriesMap := make(map[string][]ResponseTechnology)

		// Iterate once, build all structures
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

		// Convert the map to the final slice for JSON serialization
		categoryList := make([]ResponseCategory, 0, len(categoriesMap))
		for catName, techs := range categoriesMap {
			categoryList = append(categoryList, ResponseCategory{
				Category:     catName,
				Technologies: techs,
			})
		}

		// Sort categories for deterministic output
		sort.Slice(categoryList, func(i, j int) bool {
			return categoryList[i].Category < categoryList[j].Category
		})

		// Build the final response object
		response := AnalyzeResponse{
			URL:          targetURL,
			Technologies: allTechs,
			Categories:   categoryList,
		}

		// Set content type and marshal to JSON
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, fmt.Sprintf("Error encoding response: %v", err), http.StatusInternalServerError)
			return
		}
	})

	// Start the server with the correct listen address
	fmt.Printf("Server running on %s\n", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}
