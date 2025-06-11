#!/bin/bash
set -e

echo "🔧 Installing dependencies..."
export GOTOOLCHAIN=auto
go mod download

echo "🏗️ Building application..."
mkdir -p bin

# Build with explicit flags
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o bin/server \
    ./cmd/server

echo "✅ Build completed!"

# Check if binary exists
if [ -f "bin/server" ]; then
    echo "📦 Binary created successfully at: bin/server"
    echo "🔍 Binary size: $(du -h bin/server 2>/dev/null | cut -f1 || echo 'unknown')"
    
    # Make sure it's executable
    chmod +x bin/server
    
    echo "🎯 Binary is ready for deployment"
else
    echo "❌ Error: Binary not created!"
    exit 1
fi