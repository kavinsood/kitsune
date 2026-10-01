package profiler

import (
	"strings"
)

// normalizeHeaders returns the headers keyed by lowercased name, keeping
// every value separately, as wappalyzer matches header patterns against
// each value.
func normalizeHeaders(headers map[string][]string) map[string][]string {
	normalized := make(map[string][]string, len(headers))
	for name, values := range headers {
		name = strings.ToLower(name)
		normalized[name] = append(normalized[name], values...)
	}
	return normalized
}
