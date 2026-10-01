package profiler

import (
	"context"
	"github.com/miekg/dns"
	"github.com/weppos/publicsuffix-go/publicsuffix"
	"strings"
	"sync"
)

// DNSRecordTypes defines the different DNS record types to check
var DNSRecordTypes = []uint16{
	dns.TypeMX,
	dns.TypeTXT,
	dns.TypeNS,
	dns.TypeSOA,
	dns.TypeCNAME,
}

// LookupDNS returns the DNS records of a page's host, keyed by record type.
// It is checkDNS, and can be replaced to serve recorded records: the
// evaluation harness (cmd/kitsune-eval) does, to run offline.
var LookupDNS = checkDNS

// checkDNS performs DNS lookups for the given domain and returns the results
func checkDNS(domain string) map[string][]string {
	results := make(map[string][]string)
	var wg sync.WaitGroup
	var mu sync.Mutex // To protect concurrent writes to the results map

	// Extract the registrable domain from the full hostname
	// This ensures we query the main domain name, not subdomain
	registrableDomain, err := publicsuffix.Domain(domain)
	if err != nil || registrableDomain == "" {
		// If we can't extract the registrable domain, use the original domain
		registrableDomain = domain
	}

	// Use common resolvers
	resolvers := []string{
		"8.8.8.8:53",    // Google
		"1.1.1.1:53",    // Cloudflare
		"9.9.9.9:53",    // Quad9
		"208.67.222.222:53", // OpenDNS
	}

	for _, recordType := range DNSRecordTypes {
		wg.Add(1)
		go func(recordType uint16) {
			defer wg.Done()

			records := queryDNS(registrableDomain, recordType, resolvers)
			if len(records) > 0 {
				recordTypeStr := strings.ToUpper(dns.TypeToString[recordType])
				mu.Lock()
				results[recordTypeStr] = records
				mu.Unlock()
			}
		}(recordType)
	}

	wg.Wait()
	return results
}

// checkDNSWithContext performs DNS lookups with a timeout context
func checkDNSWithContext(ctx context.Context, domain string) map[string][]string {
	// Create a channel to receive the result
	resultChan := make(chan map[string][]string, 1)
	
	// Start the DNS checking in a goroutine
	go func() {
		resultChan <- LookupDNS(domain)
	}()
	
	// Wait for either the context to be done or the result to arrive
	select {
	case <-ctx.Done():
		// Context timed out or was cancelled
		return nil
	case result := <-resultChan:
		return result
	}
}