#!/bin/bash
# boundary installation script
# Usage: curl -fsSL https://raw.githubusercontent.com/coder/boundary/main/install.sh | bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO="coder/boundary"
BINARY_NAME="boundary"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
TMP_DIR="$(mktemp -d)"

# Cleanup function
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# Print banner
print_banner() {
    echo -e "${BLUE}"
    echo "  ██████╗  ██████╗ ██╗   ██╗███╗   ██╗██████╗  █████╗ ██████╗ ██╗   ██╗"
    echo "  ██╔══██╗██╔═══██╗██║   ██║████╗  ██║██╔══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝"
    echo "  ██████╔╝██║   ██║██║   ██║██╔██╗ ██║██║  ██║███████║██████╔╝ ╚████╔╝ "
    echo "  ██╔══██╗██║   ██║██║   ██║██║╚██╗██║██║  ██║██╔══██║██╔══██╗  ╚██╔╝  "
    echo "  ██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝██║  ██║██║  ██║   ██║   "
    echo "  ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   "
    echo -e "${NC}"
    echo -e "${BLUE}Network isolation tool for monitoring HTTP/HTTPS requests${NC}"
    echo
}

# Detect platform and architecture
detect_platform() {
    local os arch
    
    # Detect OS
    case "$(uname -s)" in
        Linux*)
            os="linux"
            ;;
        *)
            log_error "Unsupported operating system: $(uname -s). Only Linux is supported."
            ;;
    esac
    
    # Detect architecture
    case "$(uname -m)" in
        x86_64|amd64)
            arch="amd64"
            ;;
        arm64|aarch64)
            arch="arm64"
            ;;
        *)
            log_error "Unsupported architecture: $(uname -m). Only x86_64/amd64 and arm64/aarch64 are supported."
            ;;
    esac
    
    PLATFORM="${os}-${arch}"
    log_info "Detected platform: $PLATFORM"
}

# Check if running as root for installation
check_permissions() {
    if [[ ! -w "$INSTALL_DIR" ]]; then
        if [[ $EUID -ne 0 ]]; then
            log_warning "$INSTALL_DIR is not writable by current user."
            log_info "This script will use 'sudo' to install boundary to $INSTALL_DIR"
            log_info "You can set INSTALL_DIR environment variable to install to a different location"
            echo
            NEED_SUDO=true
        fi
    fi
}

# Get latest release version from GitHub API
get_latest_version() {
    log_info "Fetching latest release information..."
    
    local api_url="https://api.github.com/repos/$REPO/releases/latest"
    
    if command -v curl &> /dev/null; then
        VERSION=$(curl -s "$api_url" | grep '"tag_name":' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
    elif command -v wget &> /dev/null; then
        VERSION=$(wget -qO- "$api_url" | grep '"tag_name":' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
    else
        log_error "Neither curl nor wget found. Please install one of them and try again."
    fi
    
    if [[ -z "$VERSION" ]]; then
        log_error "Failed to fetch the latest release version. Please check your internet connection."
    fi
    
    # Remove 'v' prefix if present
    VERSION=${VERSION#v}
    
    log_info "Latest version: $VERSION"
}

# Download binary
download_binary() {
    local binary_name="${BINARY_NAME}-${PLATFORM}"
    local download_url="https://github.com/$REPO/releases/download/v$VERSION/${binary_name}.tar.gz"
    local archive_path="$TMP_DIR/${binary_name}.tar.gz"
    
    log_info "Downloading $binary_name v$VERSION..."
    log_info "URL: $download_url"
    
    if command -v curl &> /dev/null; then
        if ! curl -fsSL "$download_url" -o "$archive_path"; then
            log_error "Failed to download binary. Please check the URL and your internet connection."
        fi
    elif command -v wget &> /dev/null; then
        if ! wget -q "$download_url" -O "$archive_path"; then
            log_error "Failed to download binary. Please check the URL and your internet connection."
        fi
    else
        log_error "Neither curl nor wget found. Please install one of them and try again."
    fi
    
    log_success "Downloaded $binary_name.tar.gz"
    
    # Extract the binary
    log_info "Extracting binary..."
    if ! tar -xzf "$archive_path" -C "$TMP_DIR"; then
        log_error "Failed to extract the archive."
    fi
    
    BINARY_PATH="$TMP_DIR/$binary_name"
    
    # Check if binary exists and is executable
    if [[ ! -f "$BINARY_PATH" ]]; then
        log_error "Binary not found after extraction: $BINARY_PATH"
    fi
    
    chmod +x "$BINARY_PATH"
    log_success "Binary extracted and made executable"
}

# Install binary
install_binary() {
    local target_path="$INSTALL_DIR/$BINARY_NAME"
    
    log_info "Installing boundary to $target_path..."
    
    # Create install directory if it doesn't exist
    if [[ "$NEED_SUDO" == "true" ]]; then
        sudo mkdir -p "$INSTALL_DIR"
        sudo cp "$BINARY_PATH" "$target_path"
        sudo chmod +x "$target_path"
    else
        mkdir -p "$INSTALL_DIR"
        cp "$BINARY_PATH" "$target_path"
        chmod +x "$target_path"
    fi
    
    log_success "boundary installed successfully!"
}

# Verify installation
verify_installation() {
    log_info "Verifying installation..."
    
    if command -v "$BINARY_NAME" &> /dev/null; then
        local installed_version
        installed_version=$("$BINARY_NAME" --version 2>&1 | head -n1 || echo "unknown")
        log_success "boundary is available in PATH"
        log_info "Installed version: $installed_version"
    else
        log_warning "boundary is not in PATH. You may need to add $INSTALL_DIR to your PATH."
        log_info "You can run boundary using the full path: $INSTALL_DIR/$BINARY_NAME"
    fi
}

# Print usage examples
print_usage() {
    echo
    echo -e "${GREEN}🎉 Installation complete!${NC}"
    echo
    echo -e "${BLUE}Quick Start:${NC}"
    echo "  boundary --help"
    echo "  boundary --allow 'github.com' -- curl https://github.com"
    echo "  boundary --allow '*.npmjs.org' -- npm install"
    echo
    echo -e "${BLUE}Documentation:${NC}"
    echo "  https://github.com/$REPO"
    echo
}

# Check for required tools
check_requirements() {
    local missing_tools=()
    
    for tool in tar uname; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if ! command -v curl &> /dev/null && ! command -v wget &> /dev/null; then
        missing_tools+=("curl or wget")
    fi
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}. Please install them and try again."
    fi
}

# Main installation function
main() {
    print_banner
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --version)
                if [[ -n $2 ]]; then
                    VERSION="$2"
                    shift 2
                else
                    log_error "--version requires a version number"
                fi
                ;;
            --install-dir)
                if [[ -n $2 ]]; then
                    INSTALL_DIR="$2"
                    shift 2
                else
                    log_error "--install-dir requires a directory path"
                fi
                ;;
            -h|--help)
                echo "boundary installation script"
                echo
                echo "Usage: $0 [OPTIONS]"
                echo
                echo "Options:"
                echo "  --version VERSION     Install specific version (default: latest)"
                echo "  --install-dir DIR     Install directory (default: /usr/local/bin)"
                echo "  -h, --help            Show this help message"
                echo
                echo "Environment variables:"
                echo "  INSTALL_DIR           Install directory (default: /usr/local/bin)"
                echo
                echo "Examples:"
                echo "  $0                                    # Install latest version"
                echo "  $0 --version 1.0.0                   # Install specific version"
                echo "  $0 --install-dir ~/.local/bin        # Install to custom directory"
                echo "  INSTALL_DIR=~/.local/bin $0          # Using environment variable"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1. Use --help for usage information."
                ;;
        esac
    done
    
    check_requirements
    detect_platform
    check_permissions
    
    # Get version if not specified
    if [[ -z "$VERSION" ]]; then
        get_latest_version
    else
        log_info "Using specified version: $VERSION"
    fi
    
    download_binary
    install_binary
    verify_installation
    print_usage
}

# Run main function
main "$@"
