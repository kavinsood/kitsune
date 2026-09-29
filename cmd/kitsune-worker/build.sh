#!/bin/sh
# Builds the Wasm module and copies the Go JS glue next to worker.mjs.
set -e
cd "$(dirname "$0")"
mkdir -p build
go run github.com/syumai/workers-go/cmd/workers-assets-gen -mode=go -o build >/dev/null
rm -f build/worker.mjs build/runtime.mjs
cp worker.mjs build/worker.mjs
GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o build/app.wasm .
ls -la build/app.wasm
