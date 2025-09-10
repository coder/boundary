# Makefile for jail

# Variables
BINARY_NAME := jail
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
	go build -ldflags="$(LDFLAGS)" -o $(BINARY_NAME) ./cmd/jail
	@echo "✓ Built $(BINARY_NAME)"

# Build for all supported platforms
.PHONY: build-all
build-all:
	@echo "Building $(BINARY_NAME) for all platforms..."
	@echo "Version: $(VERSION)"
	@mkdir -p $(BUILD_DIR)
	@echo "Building Linux amd64..."
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/jail
	@echo "Building Linux arm64..."
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/jail
	@echo "Building macOS amd64..."
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/jail
	@echo "Building macOS arm64..."
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/jail
	@echo "✓ All binaries built successfully!"
	@echo "Binaries are in the '$(BUILD_DIR)' directory:"
	@ls -la $(BUILD_DIR)/

# Run tests (needs sudo for E2E tests)
.PHONY: test
test:
	@echo "Running tests..."
	sudo go test -v -race ./...
	@echo "✓ All tests passed!"

# Run tests with coverage (needs sudo for E2E tests)
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	sudo go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "✓ Coverage report generated: coverage.html"

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