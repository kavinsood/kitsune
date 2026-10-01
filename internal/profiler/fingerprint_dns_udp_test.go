//go:build !js

package profiler

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// TestQueryDNSTruncatedRetriesTCP checks that queries advertise a large
// EDNS0 buffer and that a truncated UDP answer is retried over TCP.
func TestQueryDNSTruncatedRetriesTCP(t *testing.T) {
	txt := strings.Repeat("x", 200)
	handler := func(tcp bool) dns.HandlerFunc {
		return func(w dns.ResponseWriter, req *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(req)
			if opt := req.IsEdns0(); opt == nil || opt.UDPSize() < ednsBufferSize {
				t.Errorf("query without a %d byte EDNS0 buffer: %v", ednsBufferSize, opt)
			}
			if !tcp {
				m.Truncated = true
			} else {
				m.Answer = append(m.Answer, &dns.TXT{
					Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET},
					Txt: []string{"V=spf1", txt},
				})
			}
			w.WriteMsg(m)
		}
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	l, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		pc.Close()
		t.Skip(err)
	}
	udp := &dns.Server{PacketConn: pc, Handler: handler(false)}
	tcp := &dns.Server{Listener: l, Handler: handler(true)}
	for _, s := range []*dns.Server{udp, tcp} {
		started := make(chan struct{})
		s.NotifyStartedFunc = func() { close(started) }
		go s.ActivateAndServe()
		<-started
		defer s.Shutdown()
	}

	got := queryDNS("example.com", dns.TypeTXT, []string{pc.LocalAddr().String()})
	if want := "v=spf1 " + txt; len(got) != 1 || got[0] != want {
		t.Errorf("queryDNS = %q, want [%q]", got, want)
	}
}
