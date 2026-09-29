package profiler

import (
	"encoding/json"
	"strconv"
)

// The embedded fingerprints and categories are compiled into
// zz_generated_fingerprints.go. Regenerate it after changing
// assets/fingerprints_data.json or assets/categories_data.json, or the code
// that compiles them; TestGeneratedFingerprintsUpToDate checks that it is
// current.
//
// The kitsune_gen_bootstrap tag builds the package without the generated
// file, so kitsune-gen still builds when the generated file doesn't compile.
//
//go:generate go run -tags kitsune_gen_bootstrap ../../cmd/kitsune-gen -o zz_generated_fingerprints.go ../../assets/fingerprints_data.json ../../assets/categories_data.json

// categoriesMapping maps category IDs to categories.
var categoriesMapping = generatedCategories

// Categories related types moved to fingerprints.go
type categoryItem struct {
	Name     string
	Priority int
}

// parseCategories decodes categories from their JSON form.
func parseCategories(categoriesData []byte) (map[int]categoryItem, error) {
	var data map[string]map[string]interface{}
	if err := json.Unmarshal(categoriesData, &data); err != nil {
		return nil, err
	}

	categories := make(map[int]categoryItem)
	for categoryIDStr, category := range data {
		categoryID, err := strconv.Atoi(categoryIDStr)
		if err != nil {
			continue
		}

		name, ok := category["name"].(string)
		if !ok {
			continue
		}

		priority := 0
		if priorityVal, ok := category["priority"].(float64); ok {
			priority = int(priorityVal)
		}

		categories[categoryID] = categoryItem{
			Name:     name,
			Priority: priority,
		}
	}
	return categories, nil
}
