### README.md

# Kitsune 🦊

Kitsune is a high-performance, standalone web technology profiler for Go. It's inspired by Wappalyzer but designed as a dependency-free library and server with a focus on speed, accuracy, and a robust data pipeline.

### Core Features

  * **High-Coverage Detection:** Identifies web technologies using a wide array of vectors:
      * URL Patterns
      * HTML DOM Content (CSS Selectors, text, and attribute matching)
      * HTTP Headers & Cookies
      * Script `src` URLs & Inline JS Variables
      * `robots.txt` Content
      * DNS Records (TXT, MX, etc.)
      * TLS Certificate Issuers
  * **Blazing Fast & Concurrent:** Performs all network I/O (page fetch, DNS, asset fetching) in parallel to minimize analysis time.
  * **Self-Contained:** Embeds all fingerprint data directly into the binary. No runtime network dependencies or database connections needed for analysis.
  * **Robust & Safe:**
      * The data pipeline validates and pre-compiles all regex patterns to ensure runtime safety.
      * Regex execution is protected with timeouts to prevent ReDoS attacks.
      * The server validates incoming URLs to prevent SSRF vulnerabilities.
  * **Simple API:** A clean, easy-to-use Go library and a straightforward JSON API server.

-----

## Getting Started

You can use Kitsune as a Go library in your own project or run it as a standalone server.

### As a Library

1.  Install the package:

    ```sh
    go get github.com/kavinsood/kitsune/kitsune
    ```

2.  Use it in your code:

    ```go
    package main

    import (
    	"fmt"
    	"io"
    	"log"
    	"net/http"

    	"github.com/kavinsood/kitsune/internal/profiler"
    )

    func main() {
    	// 1. Create a new Kitsune client
    	client, err := profiler.New()
    	if err != nil {
    		log.Fatalf("Failed to create Kitsune client: %v", err)
    	}

    	// 2. Fetch the target website
    	targetURL := "https://hackerone.com"
    	resp, err := http.Get(targetURL)
    	if err != nil {
    		log.Fatalf("Failed to fetch URL: %v", err)
    	}
    	defer resp.Body.Close()

    	body, err := io.ReadAll(resp.Body)
    	if err != nil {
    		log.Fatalf("Failed to read response body: %v", err)
    	}

    	// 3. Analyze the response to get detailed technology info
    	// This method runs the full analysis pipeline, including DNS, TLS, etc.
    	techInfo := client.FingerprintWithInfoAndURL(resp.Header, body, targetURL)

    	fmt.Printf("Detected %d technologies on %s:\n", len(techInfo), targetURL)
    	for techName, details := range techInfo {
    		// The key contains the app name and version, e.g., "React:18.2.0"
    		fmt.Printf("- %s\n", techName)
    		fmt.Printf("  - Description: %s\n", details.Description)
    		fmt.Printf("  - Website: %s\n", details.Website)
    		fmt.Printf("  - Categories: %v\n", details.Categories)
    	}
    }
    ```

### As a Server

The server provides a simple JSON API for on-demand analysis.

1.  Run the server:

    ```sh
    go run ./cmd/kitsune-api/main.go
    ```

    The server will start on port `8080`.

2.  Query the `/analyze` endpoint:

    ```sh
    curl -X POST http://localhost:8080/analyze \
         -H "Content-Type: application/json" \
         -d '{"url": "https://hackerone.com"}'
    ```

    **Example Response:**

    ```json
    {
        "technologies": [
            {
                "name": "Ruby on Rails",
                "description": "Ruby on Rails is a server-side web application framework written in Ruby.",
                "website": "http://rubyonrails.org"
            },
            {
                "name": "React",
                "description": "React is an open-source JavaScript library for building user interfaces or UI components.",
                "website": "https://react.dev"
            }
        ]
    }
    ```

### As a Cloudflare Worker

`cmd/kitsune-worker` builds the same API to Go `js/wasm` and serves it from a
Cloudflare Worker. This is how it runs in production, behind
[sherlockd](https://sherlockd.kavinsood.com) via a service binding.

```sh
cd cmd/kitsune-worker
npm install
npx wrangler dev      # local, on :8787
npx wrangler deploy   # builds with ./build.sh, then deploys
```

Pages are fetched over raw TCP sockets so origins see a normal client and
their real `Server` header comes through; sites hosted on Cloudflare fall back
to `fetch`. `cmd/kitsune-worker/tail` is an optional tail consumer that keeps
recent request events (CPU time, memory, cold starts) in KV.

-----

### Architecture & Data

Kitsune's reliability comes from its unique data pipeline.

  * **Data Sources:** The fingerprints (`assets/fingerprints_data.json`, `assets/categories_data.json`) merge four Wappalyzer-format sources, ranked highest first:
    1. the latest Wappalyzer extension, from both the Chrome Web Store (`.crx`) and addons.mozilla.org (`.xpi`), with the newer version ranked first;
    2. [enthec/webappanalyzer](https://github.com/enthec/webappanalyzer), at a pinned commit;
    3. [HTTPArchive/wappalyzer](https://github.com/HTTPArchive/wappalyzer), at a pinned commit.

    A tech's patterns are unioned across the sources. Where sources disagree on a single value (a header's pattern, a dom check, the categories, the description), the higher-ranked source wins.
  * **Overrides:** `assets/overrides.json` holds kitsune's own fixes and additions: noisy patterns removed or narrowed, and rules added for modern frameworks. It is applied on top of the merged sources and can `remove`, `set` and `add` fields per tech. Its schema is documented in `cmd/update-fingerprints/overrides.go`.
  * **Offline Pipeline:** `cmd/update-fingerprints` fetches, normalizes, merges and lints the data. It rewrites JavaScript-only regex syntax into RE2 where the meaning allows, and drops what still doesn't compile. It also checks references between techs, categories, selectors and over-broad patterns. Lint errors not listed in `assets/lint_baseline.txt` fail the run.

#### Updating the fingerprints

```sh
go run ./cmd/update-fingerprints     # download the sources, merge, lint, write assets/
go generate ./internal/profiler      # regenerate the compiled fingerprints
go test ./...
```

Useful flags:

  * `-enthec-ref` and `-httparchive-ref` move the pinned commits; they also accept branch names.
  * `-chrome`, `-extension` (Firefox), `-enthec` and `-httparchive` use local copies (directories or `.crx`/`.xpi`/`.zip` archives) instead of downloading.
  * `-sources` picks the sources and their ranking.
  * `-v` prints every lint finding.
  * `-accept-lint` accepts the current lint errors into the baseline.
  * `-corpus dir` runs the new data over saved pages and lists techs detected on too many of them.

To fix a tech, edit `assets/overrides.json` rather than the generated JSON.

To measure a change, run `go run ./cmd/kitsune-eval -tag before` before it and `go run ./cmd/kitsune-eval -compare before` after it. This scores detection on two labeled sets of pages, served from a local snapshot. See [cmd/kitsune-eval/README.md](cmd/kitsune-eval/README.md), and its note on snapshot drift.

For a deep dive into the engineering decisions, see [DESIGN.md](DESIGN.md).

### Contributing

Pull requests are welcome\! Please ensure your code passes the linter and tests.

## Acknowledgements

Kitsune is derived from the excellent [wappalyzergo](https://github.com/projectdiscovery/wappalyzergo) project, which itself is inspired by the [Wappalyzer](https://www.wappalyzer.com/) project. This project builds upon that foundation with additional optimizations, features, and architectural improvements.

### License

This project is licensed under the MIT License.
