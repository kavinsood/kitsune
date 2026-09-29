//go:build js && wasm

package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/syumai/workers-go/cloudflare/sockets"
)

// socketTransport fetches pages over raw TCP sockets (Workers' connect() API)
// instead of the fetch API. Fetch subrequests are marked as coming from a
// Worker and have their Server header replaced with "cloudflare", which both
// gets them blocked (e.g. Hacker News answers 419) and hides the origin's
// real server. Sockets see the origin's response as-is.
//
// connect() refuses Cloudflare's own IP ranges, so for sites hosted on
// Cloudflare it falls back to fetch, where "Server: cloudflare" is accurate.
type socketTransport struct {
	socket   *http.Transport
	fallback http.RoundTripper

	mu sync.Mutex
	// fetchHosts holds hosts whose sockets were refused, so later requests
	// in this isolate skip straight to fetch.
	fetchHosts map[string]bool
}

func newSocketTransport(fallback http.RoundTripper) *socketTransport {
	dial := func(secure sockets.SecureTransport) func(context.Context, string, string) (net.Conn, error) {
		return func(ctx context.Context, _, addr string) (net.Conn, error) {
			return sockets.Connect(ctx, addr, &sockets.SocketOptions{SecureTransport: secure})
		}
	}
	return &socketTransport{
		socket: &http.Transport{
			// Setting a dialer makes net/http use its own HTTP/1.1 client
			// rather than fetch. TLS is terminated by the socket itself.
			DialContext:    dial(sockets.SecureTransportOff),
			DialTLSContext: dial(sockets.SecureTransportOn),
			// Workers I/O objects can't outlive the request that created
			// them, so pooled connections would fail on the next request.
			DisableKeepAlives: true,
			// Decompressing in Wasm costs CPU; ask for identity instead.
			DisableCompression:    true,
			ResponseHeaderTimeout: 10 * time.Second,
		},
		fallback:   fallback,
		fetchHosts: map[string]bool{},
	}
}

func (t *socketTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Hostname()
	t.mu.Lock()
	useFetch := t.fetchHosts[host]
	t.mu.Unlock()
	if useFetch || req.Body != nil {
		return t.fallback.RoundTrip(req)
	}

	resp, err := t.socket.RoundTrip(req)
	if err == nil || req.Context().Err() != nil {
		return resp, err
	}
	log.Printf("socket to %s failed, falling back to fetch: %v", host, err)
	t.mu.Lock()
	t.fetchHosts[host] = true
	t.mu.Unlock()
	return t.fallback.RoundTrip(req)
}
