//go:build !js

package profiler

import (
	"strings"
	"time"

	"github.com/miekg/dns"
)

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
