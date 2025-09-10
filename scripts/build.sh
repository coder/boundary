#!/bin/bash

# Build script for jail - creates binaries for all supported platforms

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get version from git tag or use dev
VERSION=$(git describe --tags --exact-match 2>/dev/null || echo "dev-$(git rev-parse --short HEAD)")

echo -e "${BLUE}Building jail binaries...${NC}"
echo -e "${YELLOW}Version: $VERSION${NC}"
echo

# Create build directory
BUILD_DIR="build"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Build configurations: OS:ARCH:NAME
configs=(
    "linux:amd64:jail-linux-amd64"
    "linux:arm64:jail-linux-arm64"
    "darwin:amd64:jail-darwin-amd64"
    "darwin:arm64:jail-darwin-arm64"
)

# Build each configuration
for config in "${configs[@]}"; do
    IFS=':' read -r goos goarch name <<< "$config"
    
    echo -e "${YELLOW}Building $name...${NC}"
    
    env GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 go build \
        -ldflags="-s -w -X main.version=$VERSION" \
        -o "$BUILD_DIR/$name" .
    
    if [ $? -eq 0 ]; then
        size=$(du -h "$BUILD_DIR/$name" | cut -f1)
        echo -e "${GREEN}✓ Built $name ($size)${NC}"
    else
        echo -e "${RED}✗ Failed to build $name${NC}"
        exit 1
    fi
done

echo
echo -e "${GREEN}All binaries built successfully!${NC}"
echo -e "${BLUE}Binaries are in the '$BUILD_DIR' directory:${NC}"
ls -la "$BUILD_DIR"/

echo
echo -e "${YELLOW}To create release archives:${NC}"
echo "  cd $BUILD_DIR"
echo "  tar -czf jail-linux-amd64.tar.gz jail-linux-amd64"
echo "  tar -czf jail-darwin-amd64.tar.gz jail-darwin-amd64"
echo "  # ... etc for other platforms"