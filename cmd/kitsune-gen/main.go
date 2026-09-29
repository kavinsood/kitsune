// Command kitsune-gen compiles the embedded fingerprints into Go source, so
// that profiler.New doesn't have to decode and compile them at startup. It
// is run by go generate in internal/profiler:
//
//	go generate ./internal/profiler
//
// Usage:
//
//	kitsune-gen -o zz_generated_fingerprints.go fingerprints_data.json categories_data.json
package main

import (
	"flag"
	"fmt"
	"go/format"
	"log"
	"os"

	"github.com/kavinsood/kitsune/internal/profiler"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("kitsune-gen: ")
	out := flag.String("o", "", "output file (default stdout)")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: kitsune-gen [-o output.go] fingerprints.json categories.json\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(2)
	}

	fingerprints, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}
	categories, err := os.ReadFile(flag.Arg(1))
	if err != nil {
		log.Fatal(err)
	}
	src, err := profiler.GenerateFingerprintsSource(fingerprints, categories)
	if err != nil {
		log.Fatal(err)
	}
	if src, err = format.Source(src); err != nil {
		log.Fatalf("formatting generated source: %v", err)
	}

	if *out == "" {
		os.Stdout.Write(src)
		return
	}
	if err := os.WriteFile(*out, src, 0o644); err != nil {
		log.Fatal(err)
	}
}
