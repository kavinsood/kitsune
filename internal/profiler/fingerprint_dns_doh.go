//go:build js

package profiler

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Workers can't send UDP, so under js/wasm DNS goes over HTTPS (which the Go
// runtime routes through fetch). The resolvers argument is ignored.
var dohClient = &http.Client{Timeout: 2 * time.Second}

type dohResponse struct {
	Answer []struct {
		Type uint16 `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

func queryDNS(domain string, qtype uint16, _ []string) []string {
	u := "https://cloudflare-dns.com/dns-query?name=" + url.QueryEscape(domain) + "&type=" + dns.TypeToString[qtype]
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := dohClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil
	}
	var r dohResponse
	if json.Unmarshal(body, &r) != nil {
		return nil
	}

	var records []string
	for _, ans := range r.Answer {
		if ans.Type != qtype {
			continue
		}
		var value string
		fields := strings.Fields(ans.Data)
		switch qtype {
		case dns.TypeMX:
			// "10 mx.example.com."
			if len(fields) == 2 {
				value = fields[1]
			}
		case dns.TypeTXT:
			// "\"v=spf1 ...\"" possibly split into several quoted strings
			value = strings.ReplaceAll(strings.Trim(ans.Data, `"`), `" "`, " ") // matches the UDP path's Join(txt, " ")
		case dns.TypeSOA:
			// "ns1.example.com. hostmaster.example.com. 1 2 3 4 5"
			if len(fields) > 0 {
				value = fields[0]
			}
		default:
			value = ans.Data
		}
		if value != "" {
			records = append(records, strings.ToLower(value))
		}
	}
	return records
}
