package main

import (
	"encoding/json"
	"log"
	"os"

	"github.com/kavinsood/kitsune/internal/pipeline"
)

func main() {
	log.Println("=> Fetching and processing data from Wappalyzer XPI...")

	// This new function does all the work of downloading, unzipping, and merging.
	mergedApps, categoriesData, err := pipeline.FetchFromXPI()
	if err != nil {
		log.Fatalf("Failed to fetch from XPI: %v", err)
	}

	// --- The rest of your pipeline remains the same ---

	// 1. Wrap the merged apps data for normalization.
	dataToNormalize := map[string]interface{}{"apps": mergedApps}
	jsonBytes, err := json.Marshal(dataToNormalize)
	if err != nil {
		log.Fatalf("Failed to marshal merged data: %v", err)
	}

	log.Println("Normalizing data...")
	// 2. Normalize, Lint, and Write the final fingerprints in-memory.
	normalizedData, err := pipeline.NormalizeFromBytes(jsonBytes)
	if err != nil {
		log.Fatalf("Normalization failed: %v", err)
	}

	log.Println("Linting data...")
	if err := pipeline.Lint(normalizedData); err != nil {
		log.Fatalf("Linting failed: %v", err)
	}

	finalFingerprintPath := "kitsune/fingerprints_data.json"
	if err := os.WriteFile(finalFingerprintPath, normalizedData, 0644); err != nil {
		log.Fatalf("Failed to write final fingerprint data: %v", err)
	}
	log.Printf("Successfully wrote final data to %s", finalFingerprintPath)

	// 4. Write the new categories data.
	finalCategoriesPath := "kitsune/categories_data.json"
	if err := os.WriteFile(finalCategoriesPath, categoriesData, 0644); err != nil {
		log.Fatalf("Failed to write categories data: %v", err)
	}
	log.Printf("Successfully wrote categories data to %s", finalCategoriesPath)
}
