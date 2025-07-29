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
	fingerprints string
	cateogriesData string

	syncOnce          sync.Once
	categoriesMapping map[int]categoryItem
)

func init() {
	// Load data from assets package
	fingerprints = assets.FingerprintsJSON
	cateogriesData = assets.CategoriesJSON
	
	// Lazy initialize categories mapping
	syncOnce.Do(func() {
		var data map[int]map[string]string
		err := json.Unmarshal([]byte(cateogriesData), &data)
		if err != nil {
			// handle error silently
			return
		}

		categoriesMapping = make(map[int]categoryItem)
		for categoryID, category := range data {
			priorityInt, _ := strconv.Atoi(category["priority"])
			categoriesMapping[categoryID] = categoryItem{
				Name:     category["name"],
				Priority: priorityInt,
			}
		}
	})
}

// Categories related types moved to fingerprints.go
type categoryItem struct {
	Name     string
	Priority int
}