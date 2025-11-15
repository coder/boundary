# Releases

This document describes how boundary binaries are built and released.

## Automated Releases

### GitHub Releases

Binaries are automatically built and released when you push a version tag:

```bash
# Create and push a version tag
git tag v1.0.0
git push origin v1.0.0
```

This triggers the **Release** workflow which:
1. Builds binaries for all supported platforms
2. Creates compressed archives (`.tar.gz` for Unix)
3. Creates a GitHub release with all binaries attached
4. Generates release notes with download instructions

### Supported Platforms

| Platform | Architecture | Binary Name | Archive |
|----------|--------------|-------------|----------|
| Linux | x64 | `boundary-linux-amd64` | `.tar.gz` |
| Linux | ARM64 | `boundary-linux-arm64` | `.tar.gz` |


## Version Naming

- **Stable releases**: `v1.0.0`, `v1.2.3`
- **Pre-releases**: `v1.0.0-beta.1`, `v1.0.0-rc.1`
- **Development**: `dev-{git-hash}` (automatic)

Pre-releases (containing `-`) are automatically marked as "pre-release" on GitHub.

## Installation

### Quick Install (Recommended)

**Basic Installation**
```bash
# Install latest version
curl -fsSL https://raw.githubusercontent.com/coder/boundary/main/install.sh | bash
```

**Custom Installation Options**
```bash
# Install specific version
curl -fsSL https://raw.githubusercontent.com/coder/boundary/main/install.sh | bash -s -- --version v1.0.0

# Install to custom directory
curl -fsSL https://raw.githubusercontent.com/coder/boundary/main/install.sh | bash -s -- --install-dir ~/.local/bin

# Download and run locally
wget https://raw.githubusercontent.com/coder/boundary/main/install.sh
chmod +x install.sh
./install.sh --help
```

### Manual Installation

#### From GitHub Releases

1. Go to [Releases](https://github.com/coder/boundary/releases)
2. Download the appropriate binary for your platform
3. Extract the archive
4. Make executable (Unix): `chmod +x boundary`
5. Move to PATH: `sudo mv boundary /usr/local/bin/`

#### Platform-Specific Commands

**Linux (x86_64)**
```bash
curl -fsSL https://github.com/coder/boundary/releases/latest/download/boundary-linux-amd64.tar.gz | tar -xz
sudo mv boundary-linux-amd64 /usr/local/bin/boundary
boundary --help
```

**Linux (ARM64)**
```bash
curl -fsSL https://github.com/coder/boundary/releases/latest/download/boundary-linux-arm64.tar.gz | tar -xz
sudo mv boundary-linux-arm64 /usr/local/bin/boundary
boundary --help
```



### Verify Installation

```bash
boundary --help
```