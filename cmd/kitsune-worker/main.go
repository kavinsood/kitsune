//go:build js && wasm

// Command kitsune-worker serves the Kitsune API from a Cloudflare Worker.
// Build with ./build.sh; see worker.mjs for how the module is instantiated.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/kavinsood/kitsune/internal/api"
	"github.com/kavinsood/kitsune/internal/profiler"
	"github.com/syumai/workers-go"
	"github.com/syumai/workers-go/cloudflare/fetch"
)

// memoryLimit leaves headroom under the 128MB isolate cap for the JS heap and
// Go runtime overhead outside the GC'd heap.
const memoryLimit = 80 << 20

func main() {
	// net/http's built-in js transport calls fetch with the wrong `this` under
	// workers-go's global proxy, which workerd rejects as an illegal invocation.
	http.DefaultTransport = fetch.NewClient().HTTPClient(fetch.RedirectModeFollow).Transport
	api.PageClient = &http.Client{Transport: newSocketTransport(http.DefaultTransport), Timeout: 15 * time.Second}

	// Workers kills isolates above 128MB, and Go's Wasm linear memory never
	// shrinks. A soft limit makes the GC collect harder instead of growing it.
	debug.SetMemoryLimit(memoryLimit)

	start := time.Now()
	engine, err := profiler.New()
	if err != nil {
		log.Fatalf("Failed to initialize profiler engine: %v", err)
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	line, _ := json.Marshal(map[string]any{
		"event":         "init",
		"init_ms":       time.Since(start).Milliseconds(),
		"heap_alloc_mb": m.HeapAlloc >> 20,
		"sys_mb":        m.Sys >> 20,
	})
	log.Println(string(line))

	// Unlike workers.Serve, don't exit after the first request: worker.mjs
	// keeps one instance per isolate so init cost is paid once.
	workers.ServeNonBlock(recoverer(api.NewMux(engine)))
	workers.Ready()
	select {}
}

// recoverer keeps a handler panic from exiting the Go program, which would
// break every later request served by this isolate.
func recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("panic: %v\n%s", err, debug.Stack())
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
