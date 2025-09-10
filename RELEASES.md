# Releases

This document describes how jail binaries are built and released.

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
| Linux | x64 | `jail-linux-amd64` | `.tar.gz` |
| Linux | ARM64 | `jail-linux-arm64` | `.tar.gz` |
| macOS | Intel | `jail-darwin-amd64` | `.tar.gz` |
| macOS | Apple Silicon | `jail-darwin-arm64` | `.tar.gz` |

## Release Process

### For Maintainers

1. **Prepare Release**:
   - Ensure all changes are merged to `main`
   - Update version in relevant files if needed
   - Test the build locally

2. **Create Release**:
   ```bash
   # Create and push version tag
   git tag v1.2.3
   git push origin v1.2.3
   ```

3. **Verify Release**:
   - Check GitHub Actions completed successfully
   - Verify release appears in GitHub Releases
   - Test download and installation of binaries

### Version Naming

- **Stable releases**: `v1.0.0`, `v1.2.3`
- **Pre-releases**: `v1.0.0-beta.1`, `v1.0.0-rc.1`
- **Development**: `dev-{git-hash}` (automatic)

Pre-releases (containing `-`) are automatically marked as "pre-release" on GitHub.

## Installation

### From GitHub Releases

1. Go to [Releases](https://github.com/coder/jail/releases)
2. Download the appropriate binary for your platform
3. Extract the archive
4. Make executable (Unix): `chmod +x jail`
5. Move to PATH: `sudo mv jail /usr/local/bin/`

### Verify Installation

```bash
jail --help
```

## Troubleshooting

### Release Issues

- **Tag not triggering release**: Ensure tag follows `v*` pattern
- **Build failures**: Check GitHub Actions logs
- **Missing binaries**: Verify all matrix builds completed successfully
