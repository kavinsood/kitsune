# Kitsune 🦊

Kitsune is a high-performance, standalone web technology profiler for Go. It's inspired by Wappalyzer but designed as a dependency-free library and server with a focus on speed, accuracy, and a robust data pipeline.

### Core Features

* **High-Coverage Detection:** Identifies web technologies using a wide array of vectors:
    * URL Patterns
    * HTML DOM Content (CSS Selectors)
    * HTTP Headers & Cookies
    * Script `src` URLs & Inline JS Variables
    * `robots.txt` Content
    * DNS Records (TXT, MX)
    * TLS Certificate Issuers
* **Blazing Fast & Concurrent:** Performs all network I/O (page fetch, DNS, etc.) in parallel to minimize analysis time.
* **Self-Contained:** Embeds all fingerprint data directly into the binary. No runtime network dependencies or database connections needed.
* **Robust & Safe:**
    * All regex patterns are pre-compiled and validated at build time.
    * Regex execution is protected with timeouts to prevent ReDoS.
    * The server uses `safeurl` to prevent SSRF vulnerabilities.
* **Simple API:** A clean, easy-to-use Go library and a straightforward JSON API server.

---

## Getting Started

You can use Kitsune as a Go library in your own project or run it as a standalone server.

### As a Library

1.  Install the package:
    ```sh
    go get [github.com/kavinsood/kitsune/kitsune](https://github.com/kavinsood/kitsune/kitsune)
    ```

2.  Use it in your code:

    ```go
    package main

    import (
    	"fmt"
    	"log"

    	"[github.com/kavinsood/kitsune/kitsune](https://github.com/kavinsood/kitsune/kitsune)"
    )

    func main() {
    	client, err := kitsune.New()
    	if err != nil {
    		log.Fatalf("Failed to create Kitsune client: %v", err)
    	}

    	targetURL := "[https://hackerone.com](https://hackerone.com)"
    	technologies, err := client.FingerprintURL(targetURL)
    	if err != nil {
    		log.Fatalf("Failed to fingerprint URL: %v", err)
    	}

    	fmt.Printf("Detected %d technologies on %s:\n", len(technologies), targetURL)
    	for tech, details := range technologies {
    		if details.Version != "" {
    			fmt.Printf("- %s (Version: %s)\n", tech, details.Version)
    		} else {
    			fmt.Printf("- %s\n", tech)
    		}
    	}
    }
    ```

### As a Server

The server provides a simple JSON API for on-demand analysis.

1.  Run the server:
    ```sh
    go run ./cmd/server/main.go
    ```
    The server will start on port `8080`.

2.  Query the `/analyze` endpoint:
    ```sh
    curl -X POST http://localhost:8080/analyze \
         -H "Content-Type: application/json" \
         -d '{"url": "[https://hackerone.com](https://hackerone.com)"}'
    ```

    **Example Response:**
    ```json
    {
      "url": "[https://hackerone.com](https://hackerone.com)",
      "technologies": {
        "Google Font API": {
          "Version": ""
        },
        "Handlebars": {
          "Version": ""
        },
        "Marketo": {
          "Version": ""
        },
        "Ruby on Rails": {
          "Version": ""
        },
        ...
      }
    }
    ```

---

### Architecture & Data

Kitsune's reliability comes from its unique data pipeline.

* **Data Source:** Fingerprints are sourced directly from the official Wappalyzer browser extension (`.xpi` file), ensuring the data is canonical and comprehensive.
* **Offline Pipeline:** A Go-based utility in `cmd/kitsune-updater` handles fetching, normalizing, and linting this data. It converts the flexible source schema into a strict, pre-validated format that the runtime can use safely and efficiently.

For a deep dive into the engineering decisions, see [DESIGN.md](DESIGN.md).

### Contributing

Pull requests are welcome! Please ensure your code passes the linter and tests.

### License

This project is licensed under the MIT License.