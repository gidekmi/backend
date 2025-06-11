#!/bin/bash

echo "🔧 Installing dependencies..."
go mod download

echo "🏗️ Building application..."
mkdir -p bin
go build -o bin/server ./cmd/server

echo "✅ Build completed!"
echo "📦 Binary created at: bin/server"
echo "🔍 Binary size: $(du -h bin/server | cut -f1)"