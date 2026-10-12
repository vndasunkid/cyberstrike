#!/bin/bash

# Build script for CyberStrike standalone binary (Linux x64)

set -e

echo "🧹 Cleaning previous build artifacts..."
rm -rf packages/cyberstrike/dist

echo "🔨 Building standalone binary for Linux x64..."
bun run --cwd packages/cyberstrike build --single

echo "✅ Build complete!"
echo "📦 Binary location: ./packages/cyberstrike/dist/cyberstrike-linux-x64/bin/cyberstrike"
echo ""
echo "To run the binary:"
echo "  ./packages/cyberstrike/dist/cyberstrike-linux-x64/bin/cyberstrike"
