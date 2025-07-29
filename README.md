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

-----

### Architecture & Data

Kitsune's reliability comes from its unique data pipeline.

  * **Data Source:** Fingerprints are sourced directly from the official Wappalyzer browser extension (`.xpi` file), ensuring the data is canonical and comprehensive.
  * **Offline Pipeline:** A Go-based utility in `cmd/update-fingerprints` handles fetching, normalizing, and linting this data. It converts the flexible source schema into a strict, pre-validated format that the runtime can use safely and efficiently.

For a deep dive into the engineering decisions, see [DESIGN.md](DESIGN.md).

### Contributing

Pull requests are welcome\! Please ensure your code passes the linter and tests.

## Acknowledgements

Kitsune is derived from the excellent [wappalyzergo](https://github.com/projectdiscovery/wappalyzergo) project, which itself is inspired by the [Wappalyzer](https://www.wappalyzer.com/) project. This project builds upon that foundation with additional optimizations, features, and architectural improvements.

### License

This project is licensed under the MIT License.
