# Kitsune - Web Technology Detector

Kitsune is a high-performance web technology detection engine written in Go. It can identify web frameworks, programming languages, CMS systems, and other technologies used by websites by analyzing HTTP responses, HTML content, JavaScript, CSS, and other signals.

## Features

- Fast and lightweight technology detection
- Minimal memory footprint
- Highly concurrent detection engine with intelligent pipelining
- Detection based on multiple vectors:
  - HTTP headers
  - HTML content
  - JavaScript patterns
  - CSS patterns
  - Cookies
  - DOM structure
  - TLS certificate issuers
  - DNS records
  - Robots.txt content
- Regular expression matching with timeout protection
- Built-in fingerprint database with frequent updates

## Installation

```bash
go get github.com/kavinsood/kitsune
```

## Basic Usage

```go
package main

import (
	"fmt"
	"io"
	"net/http"

	"github.com/kavinsood/kitsune/internal/profiler"
)

func main() {
	// Create an HTTP request
	resp, err := http.Get("https://example.com")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	// Initialize the technology profiler
	engine, err := profiler.New()
	if err != nil {
		panic(err)
	}

	// Detect technologies
	technologies := engine.FingerprintWithURL(resp.Header, body, "https://example.com")

	// Print detected technologies
	fmt.Println("Detected technologies:")
	for tech := range technologies {
		fmt.Printf("- %s\n", tech)
	}

	// Get more detailed information
	techInfo := engine.FingerprintWithInfoAndURL(resp.Header, body, "https://example.com")

	fmt.Println("\nDetailed information:")
	for tech, info := range techInfo {
		fmt.Printf("- %s: %s\n", tech, info.Description)
	}
}
```

## API Server

Kitsune includes a simple API server that can be used to detect technologies via HTTP requests:

```bash
cd cmd/kitsune-api
go run main.go
```

Then make a request to the server:

```bash
curl -X POST "http://localhost:8080/analyze?url=https://example.com"
```

## Acknowledgements

Kitsune is derived from the excellent [wappalyzergo](https://github.com/projectdiscovery/wappalyzergo) project, which itself is inspired by the [Wappalyzer](https://www.wappalyzer.com/) project. This project builds upon that foundation with additional optimizations, features, and architectural improvements.
