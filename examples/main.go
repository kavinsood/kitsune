package main

import (
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/kavinsood/kitsune/internal/profiler"
)

func main() {
	resp, err := http.DefaultClient.Get("https://hackerone.com/")
	if err != nil {
		log.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body) // Ignoring error for example
	defer resp.Body.Close()

	profilerClient, err := profiler.New()
	if err != nil {
		log.Fatal(err)
	}

	// Using the enhanced detection with DNS and JavaScript analysis
	fingerprints := profilerClient.FingerprintWithURL(resp.Header, data, resp.Request.URL.String())
	fmt.Printf("Enhanced detection results: %v\n", fingerprints)

	// For comparison, also show the original detection method
	oldFingerprints := profilerClient.Fingerprint(resp.Header, data)
	fmt.Printf("Original detection results: %v\n", oldFingerprints)
}
