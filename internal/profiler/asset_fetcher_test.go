package profiler

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// failingReader returns its data and then an error, as a body cut by a
// timeout does.
type failingReader struct{ r io.Reader }

func (f *failingReader) Read(p []byte) (int, error) {
	n, err := f.r.Read(p)
	if err == io.EOF {
		return n, errors.New("timeout")
	}
	return n, err
}

func TestReadString(t *testing.T) {
	body := strings.Repeat("abcdefghij", 1000) // 10000 bytes
	tests := []struct {
		name          string
		contentLength int64
		limit, budget int64
		failing       bool
		want          int
		wantErr       bool
	}{
		{"unknown length", -1, 1 << 20, 1 << 20, false, 10000, false},
		{"known length", 10000, 1 << 20, 1 << 20, false, 10000, false},
		{"limit", -1, 4000, 1 << 20, false, 4000, false},
		{"budget", 10000, 1 << 20, 3000, false, 3000, false},
		{"no budget", 10000, 1 << 20, 0, false, 0, false},
		{"error keeps what was read", -1, 1 << 20, 1 << 20, true, 10000, true},
	}
	for _, tt := range tests {
		var r io.Reader = strings.NewReader(body)
		if tt.failing {
			r = &failingReader{r}
		}
		resp := &http.Response{Body: io.NopCloser(r), ContentLength: tt.contentLength}
		var budget atomic.Int64
		budget.Store(tt.budget)
		got, err := readString(resp, tt.limit, &budget)
		if len(got) != tt.want || got != body[:len(got)] || (err != nil) != tt.wantErr {
			t.Errorf("%s: read %d bytes, err %v; want %d, err %v", tt.name, len(got), err, tt.want, tt.wantErr)
		}
		if left := budget.Load(); left != tt.budget-int64(len(got)) {
			t.Errorf("%s: budget left %d, want %d", tt.name, left, tt.budget-int64(len(got)))
		}
	}
}

func TestAssetFetcherCaps(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if strings.HasSuffix(r.URL.Path, ".css") {
			w.Header().Set("Content-Type", "text/css")
		} else {
			w.Header().Set("Content-Type", "application/javascript")
		}
		io.WriteString(w, "x")
	}))
	defer srv.Close()

	var wg sync.WaitGroup
	var mu sync.Mutex
	got := map[string]int{}
	af := NewAssetFetcher(srv.URL+"/", context.Background(), &wg, 10, func(assetType, _ string) {
		mu.Lock()
		got[assetType]++
		mu.Unlock()
	})
	af.Start()
	for i := 0; i < 1000; i++ {
		af.AddURL(fmt.Sprintf("%s/%d.js", srv.URL, i), "script", 0)
		af.AddURL(fmt.Sprintf("%s/%d.css", srv.URL, i), "style", 0)
		af.AddURL(srv.URL+"/0.js", "script", 0) // a repeat counts once
	}
	af.Stop()
	wg.Wait()
	if got["script"] != maxScripts || got["style"] != maxStyles || hits.Load() != maxScripts+maxStyles {
		t.Errorf("fetched %d scripts, %d styles in %d requests; want %d, %d", got["script"], got["style"], hits.Load(), maxScripts, maxStyles)
	}
}
