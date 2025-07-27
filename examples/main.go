package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/kavinsood/kitsune/kitsune"
)

func main() {
	// A standard browser User-Agent
	userAgent := "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
	url := "https://kavinsood.com"

	// Create a new request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal(err)
	}

	// Set the User-Agent header
	req.Header.Set("User-Agent", userAgent)

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	kitsuneClient, err := kitsune.New(nil)
	if err != nil {
		log.Fatal(err)
	}
	// kitsuneClient.Debug = true // Remove debug flag

	// Use the new FingerprintURL method
	technologies, err := kitsuneClient.FingerprintURL(url)
	if err != nil {
		log.Fatal(err)
	}

	// Get category info for detected technologies
	categories := kitsuneClient.GetCategories(technologies)

	// Build a map from category name to list of technologies
	catToTechs := make(map[string][]string)
	techVersions := make(map[string]string)
	for tech, detection := range technologies {
		catInfo, ok := categories[tech]
		if !ok || len(catInfo.Names) == 0 {
			catToTechs["Uncategorized"] = append(catToTechs["Uncategorized"], tech)
		} else {
			for _, catName := range catInfo.Names {
				catToTechs[catName] = append(catToTechs[catName], tech)
			}
		}
		techVersions[tech] = detection.Version
	}

	fmt.Printf("\n===== Kitsune Detection Results (Grouped by Category) =====\n")
	for cat, techs := range catToTechs {
		fmt.Printf("\nCategory: %s\n", cat)
		for _, tech := range techs {
			fmt.Printf("  - %s\n", tech)
		}
	}

	// Debug section for problematic detections
	fmt.Printf("\n===== DEBUG: Problematic Detections =====\n")
	for tech, details := range technologies {
		// Check if it's one of the problematic detections
		if tech == "Wagtail" || tech == "SvelteKit" {
			fmt.Printf("DEBUG: Found %s\n", tech)
			fmt.Printf("  - DetectedBy: %s\n", details.DetectedBy)
			fmt.Printf("  - MatchedPattern: %s\n", details.MatchedPattern)
			fmt.Printf("  - MatchedValue: %s\n", details.MatchedValue)
			fmt.Printf("  - Version: %s\n", details.Version)
			fmt.Printf("  - Confidence: %d\n", details.Confidence)
		}
	}
	fmt.Printf("\n========================================================\n")
}
