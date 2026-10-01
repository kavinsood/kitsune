//go:build !js

package profiler

import (
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ednsBufferSize is the UDP payload size advertised with EDNS0, so that
// large answers (TXT records of big domains are often several KB) fit in
// one UDP response more often. Truncated answers are retried over TCP.
const ednsBufferSize = 4096

// queryDNS performs the actual DNS query with fallback to multiple resolvers
func queryDNS(domain string, qtype uint16, resolvers []string) []string {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true
	m.SetEdns0(ednsBufferSize, false)

	for _, resolver := range resolvers {
		r := exchangeDNS(m, resolver)
		if r == nil {
			continue
		}
		if records := dnsAnswerValues(r.Answer, qtype); len(records) > 0 {
			return records
		}
	}
	return nil
}

// exchangeDNS sends m to resolver over UDP, retrying over TCP if the answer
// is truncated, and returns the response or nil on failure.
func exchangeDNS(m *dns.Msg, resolver string) *dns.Msg {
	c := &dns.Client{Timeout: 2 * time.Second, UDPSize: ednsBufferSize}
	r, _, err := c.Exchange(m, resolver)
	if err == nil && r != nil && r.Truncated {
		c.Net = "tcp"
		if tr, _, err := c.Exchange(m, resolver); err == nil && tr != nil {
			return tr
		}
	}
	if err != nil {
		return nil
	}
	return r
}

// dnsAnswerValues returns the values of the answers of type qtype, as
// matched by dns patterns.
func dnsAnswerValues(answers []dns.RR, qtype uint16) []string {
	var records []string
	for _, ans := range answers {
		var value string
		switch qtype {
		case dns.TypeMX:
			if mx, ok := ans.(*dns.MX); ok {
				value = mx.Mx
			}
		case dns.TypeTXT:
			if txt, ok := ans.(*dns.TXT); ok {
				value = strings.Join(txt.Txt, " ")
			}
		case dns.TypeNS:
			if ns, ok := ans.(*dns.NS); ok {
				value = ns.Ns
			}
		case dns.TypeSOA:
			if soa, ok := ans.(*dns.SOA); ok {
				value = soa.Ns
			}
		case dns.TypeCNAME:
			if cname, ok := ans.(*dns.CNAME); ok {
				value = cname.Target
			}
		}
		if value != "" {
			records = append(records, strings.ToLower(value))
		}
	}
	return records
}
