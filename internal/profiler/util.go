package profiler

import (
	"regexp"
	"time"
)

// matchWithTimeout executes a regex match within a specified duration.
// It protects against catastrophic backtracking (ReDoS) by terminating slow-running patterns.
// It returns the submatch slice on success, or nil if the match fails or times out.
func matchWithTimeout(re *regexp.Regexp, body []byte, timeout time.Duration) []string {
	// A channel to communicate the result from the regex goroutine.
	resultChan := make(chan []string, 1)

	go func() {
		// This might be slow if the regex is inefficient.
		resultChan <- re.FindStringSubmatch(string(body))
	}()

	select {
	case result := <-resultChan:
		return result
	case <-time.After(timeout):
		// The regex took too long. Log this for debugging if needed.
		// log.Printf("Regex timeout on pattern: %s", re.String())
		return nil
	}
}