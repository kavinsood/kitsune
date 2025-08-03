package profiler

import (
	_ "embed"
	"encoding/json"
	"strconv"
	"sync"

	"github.com/kavinsood/kitsune/assets"
)

var (
	// Data now comes from assets package
	fingerprints   string
	categoriesData string

	syncOnce          sync.Once
	categoriesMapping map[int]categoryItem
)

func init() {
	// Load data from assets package
	fingerprints = assets.FingerprintsJSON
	categoriesData = assets.CategoriesJSON

	// Lazy initialize categories mapping
	syncOnce.Do(func() {
		var data map[string]map[string]interface{}
		err := json.Unmarshal([]byte(categoriesData), &data)
		if err != nil {
			// handle error silently
			return
		}

		categoriesMapping = make(map[int]categoryItem)
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

			categoriesMapping[categoryID] = categoryItem{
				Name:     name,
				Priority: priority,
			}
		}
	})
}

// Categories related types moved to fingerprints.go
type categoryItem struct {
	Name     string
	Priority int
}
