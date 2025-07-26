package kitsune

import (
	"regexp"
	"time"
)

// matchWithTimeout runs a regex match with a timeout to mitigate ReDoS risk.
// Returns submatches ([]string) or nil if no match or timeout.
func matchWithTimeout(re *regexp.Regexp, body []byte, timeout time.Duration) []string {
	done := make(chan []string, 1)
	go func() {
		matches := re.FindStringSubmatch(string(body))
		done <- matches
	}()
	select {
	case result := <-done:
		return result
	case <-time.After(timeout):
		// Optionally log the timeout and pattern for debugging
		return nil
	}
}
