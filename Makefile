# Makefile for boundary

# Variables
BINARY_NAME := boundary
BUILD_DIR := build
VERSION := $(shell git describe --tags --exact-match 2>/dev/null || echo "dev-$(shell git rev-parse --short HEAD)")
LDFLAGS := -s -w -X main.version=$(VERSION)

# Default target
.PHONY: all
all: build

# Build for current platform
.PHONY: build
build:
	@echo "Building $(BINARY_NAME) for current platform..."
	@echo "Version: $(VERSION)"
	go build -ldflags="$(LDFLAGS)" -o $(BINARY_NAME) ./cmd/boundary
	@echo "✓ Built $(BINARY_NAME)"

# Build for all supported platforms
.PHONY: build-all
build-all:
	@echo "Building $(BINARY_NAME) for all platforms..."
	@echo "Version: $(VERSION)"
	@mkdir -p $(BUILD_DIR)
	@echo "Building Linux amd64..."
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/boundary
	@echo "Building Linux arm64..."
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/boundary
	@# macOS builds removed; Linux only
	@echo "✓ All binaries built successfully!"
	@echo "Binaries are in the '$(BUILD_DIR)' directory:"
	@ls -la $(BUILD_DIR)/

# Download and verify dependencies
.PHONY: deps
deps:
	@echo "Downloading dependencies..."
	go mod download
	@echo "Verifying dependencies..."
	go mod verify
	@echo "✓ Dependencies ready!"

# Generate protobuf code. It is expected that code generation is done with the
# same version of protoc and protoc-gen-go as coder/coder.
.PHONY: proto
proto:
	@echo "Generating protobuf code..."
	protoc --go_out=. --go_opt=paths=source_relative proto/logs.proto
	@echo "✓ Protobuf code generated"

# Run all code generation
.PHONY: gen
gen: proto
	@echo "✓ Code generation complete"

# Run unit tests only (no sudo required)
.PHONY: unit-test
unit-test:
	@echo "Running unit tests..."
	@which go > /dev/null || (echo "Go not found in PATH" && exit 1)
	go test -v -race $$(go list ./... | grep -v e2e_tests)
	@echo "✓ Unit tests passed!"

# Run E2E tests (Linux only, needs sudo)
.PHONY: e2e-test
e2e-test:
	@echo "Running E2E tests..."
	@which go > /dev/null || (echo "Go not found in PATH" && exit 1)
	@if [ "$$(uname)" != "Linux" ]; then \
		echo "E2E tests require Linux platform. Current platform: $$(uname)"; \
		exit 1; \
	fi
	sudo $(shell which go) test -v -race ./e2e_tests -count=1
	@echo "✓ E2E tests passed!"

# Run tests with coverage (needs sudo for E2E tests)
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "✓ Coverage report generated: coverage.html"

# CI checks (deps, test, build)
.PHONY: ci
ci: deps test build
	@echo "✓ All CI checks passed!"

# CI checks with coverage
.PHONY: ci-coverage
ci-coverage: deps test-coverage build
	@echo "✓ All CI checks with coverage passed!"

# Prepare release archives
.PHONY: release-archives
release-archives: 
	@echo "Creating release archives..."
	@# Check if we should use build directory or artifacts directory
	@if [ -d "binaries" ]; then \
		echo "Using artifacts from binaries/ directory"; \
		mkdir -p archives; \
		for dir in binaries/*/; do \
			if [ -d "$$dir" ]; then \
				binary_name=$$(basename "$$dir"); \
				if [ -f "$$dir/$$binary_name" ]; then \
					echo "Creating archive for $$binary_name..."; \
					cd "$$dir" && tar -czf "../../archives/$${binary_name}.tar.gz" "$$binary_name" && cd ../..; \
				fi; \
			fi; \
		done; \
	else \
		echo "Using binaries from build/ directory"; \
		if [ ! -d "$(BUILD_DIR)" ]; then \
			echo "No binaries found. Run 'make build-all' first."; \
			exit 1; \
		fi; \
		mkdir -p $(BUILD_DIR)/archives; \
		for binary in $(BUILD_DIR)/$(BINARY_NAME)-*; do \
			if [ -f "$$binary" ]; then \
				binary_name=$$(basename "$$binary"); \
				echo "Creating archive for $$binary_name..."; \
				cd $(BUILD_DIR) && tar -czf "archives/$${binary_name}.tar.gz" "$$binary_name" && cd ..; \
			fi; \
		done; \
	fi
	@echo "✓ Release archives created!"
	@if [ -d "archives" ]; then \
		echo "Archives in archives/:"; \
		ls -la archives/; \
	else \
		echo "Archives in $(BUILD_DIR)/archives/:"; \
		ls -la $(BUILD_DIR)/archives/; \
	fi

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BINARY_NAME)
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html
	@echo "✓ Clean complete!"

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	go fmt ./...
	@echo "✓ Code formatted!"

# Lint code
.PHONY: lint
lint:
	@echo "Linting code..."
	golangci-lint run
	@echo "✓ Linting complete!"

# Show help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build              Build for current platform"
	@echo "  build-all          Build for all supported platforms"
	@echo "  deps               Download and verify dependencies"
	@echo "  test               Run tests"
	@echo "  test-coverage      Run tests with coverage report"
	@echo "  ci                 Run CI checks (deps + test + build)"
	@echo "  ci-coverage        Run CI checks with coverage"
	@echo "  release-archives   Create release archives"
	@echo "  clean              Clean build artifacts"
	@echo "  fmt                Format code"
	@echo "  lint               Lint code"
	@echo "  help               Show this help message"