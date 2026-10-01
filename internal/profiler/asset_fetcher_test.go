package profiler

import (
	"errors"
	"io"
	"net/http"
	"strings"
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
