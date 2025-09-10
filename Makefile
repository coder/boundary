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
	go build -ldflags="$(LDFLAGS)" -o $(BINARY_NAME) .
	@echo "✓ Built $(BINARY_NAME)"

# Build for all supported platforms
.PHONY: build-all
build-all:
	@echo "Building $(BINARY_NAME) for all platforms..."
	@echo "Version: $(VERSION)"
	@mkdir -p $(BUILD_DIR)
	@echo "Building Linux amd64..."
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .
	@echo "Building Linux arm64..."
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 .
	@echo "Building macOS amd64..."
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 .
	@echo "Building macOS arm64..."
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 .
	@echo "✓ All binaries built successfully!"
	@echo "Binaries are in the '$(BUILD_DIR)' directory:"
	@ls -la $(BUILD_DIR)/

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	go test -v -race ./...
	@echo "✓ All tests passed!"

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -race -coverprofile=coverage.out ./...
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

# Install binary to system PATH
.PHONY: install
install: build
	@echo "Installing $(BINARY_NAME) to /usr/local/bin..."
	sudo cp $(BINARY_NAME) /usr/local/bin/
	@echo "✓ $(BINARY_NAME) installed successfully!"

# Uninstall binary from system PATH
.PHONY: uninstall
uninstall:
	@echo "Uninstalling $(BINARY_NAME) from /usr/local/bin..."
	sudo rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "✓ $(BINARY_NAME) uninstalled successfully!"

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
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found, running go vet instead..."; \
		go vet ./...; \
	fi
	@echo "✓ Linting complete!"

# Tidy dependencies
.PHONY: tidy
tidy:
	@echo "Tidying dependencies..."
	go mod tidy
	go mod verify
	@echo "✓ Dependencies tidied!"

# Development setup
.PHONY: dev-setup
dev-setup:
	@echo "Setting up development environment..."
	go mod download
	go mod verify
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "Installing golangci-lint..."; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	fi
	@echo "✓ Development environment ready!"

# Show help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build        - Build binary for current platform"
	@echo "  build-all    - Build binaries for all supported platforms"
	@echo "  test         - Run tests"
	@echo "  test-coverage- Run tests with coverage report"
	@echo "  clean        - Clean build artifacts"
	@echo "  install      - Install binary to /usr/local/bin"
	@echo "  uninstall    - Remove binary from /usr/local/bin"
	@echo "  fmt          - Format code"
	@echo "  lint         - Lint code (requires golangci-lint)"
	@echo "  tidy         - Tidy and verify dependencies"
	@echo "  dev-setup    - Set up development environment"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make build           # Build for current platform"
	@echo "  make build-all       # Build for all platforms"
	@echo "  make test            # Run tests"
	@echo "  make clean           # Clean build artifacts"
	@echo "  make install         # Install to system PATH"
