package profiler

import (
	"context"
	"github.com/miekg/dns"
	"github.com/weppos/publicsuffix-go/publicsuffix"
	"strings"
	"sync"
	"time"
)

// DNSRecordTypes defines the different DNS record types to check
var DNSRecordTypes = []uint16{
	dns.TypeMX,
	dns.TypeTXT,
	dns.TypeNS,
	dns.TypeSOA,
	dns.TypeCNAME,
}

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

// queryDNS performs the actual DNS query with fallback to multiple resolvers
func queryDNS(domain string, qtype uint16, resolvers []string) []string {
	var records []string
	
	for _, resolver := range resolvers {
		c := new(dns.Client)
		c.Timeout = 2 * time.Second
		
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(domain), qtype)
		m.RecursionDesired = true
		
		// Try to query this resolver
		r, _, err := c.Exchange(m, resolver)
		if err != nil || r == nil || len(r.Answer) == 0 {
			continue
		}
		
		// Process each answer
		for _, ans := range r.Answer {
			var value string
			
			// Extract the relevant data based on record type
			switch qtype {
			case dns.TypeMX:
				if mx, ok := ans.(*dns.MX); ok {
					value = strings.ToLower(mx.Mx)
				}
			case dns.TypeTXT:
				if txt, ok := ans.(*dns.TXT); ok {
					value = strings.ToLower(strings.Join(txt.Txt, " "))
				}
			case dns.TypeNS:
				if ns, ok := ans.(*dns.NS); ok {
					value = strings.ToLower(ns.Ns)
				}
			case dns.TypeSOA:
				if soa, ok := ans.(*dns.SOA); ok {
					value = strings.ToLower(soa.Ns)
				}
			case dns.TypeCNAME:
				if cname, ok := ans.(*dns.CNAME); ok {
					value = strings.ToLower(cname.Target)
				}
			}
			
			if value != "" {
				records = append(records, value)
			}
		}
		
		// If we got answers, no need to try other resolvers
		if len(records) > 0 {
			break
		}
	}
	
	return records
}

// checkDNSWithContext performs DNS lookups with a timeout context
func checkDNSWithContext(ctx context.Context, domain string) map[string][]string {
	// Create a channel to receive the result
	resultChan := make(chan map[string][]string, 1)
	
	// Start the DNS checking in a goroutine
	go func() {
		resultChan <- checkDNS(domain)
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