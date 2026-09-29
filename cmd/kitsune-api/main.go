package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/kavinsood/kitsune/internal/api"
	"github.com/kavinsood/kitsune/internal/profiler"
)

func main() {
	fmt.Println("Starting Kitsune API server...")

	// Get port from environment variable (for Render) or default to 8080
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Construct the listen address with "0.0.0.0" to accept external connections
	listenAddr := "0.0.0.0:" + port

	// Initialize the profiler
	engine, err := profiler.New()
	if err != nil {
		log.Fatalf("Failed to initialize profiler engine: %v", err)
	}

	// Start the server with the correct listen address
	fmt.Printf("Server running on %s\n", listenAddr)
	log.Fatal(http.ListenAndServe(listenAddr, api.NewMux(engine)))
}
