#!/bin/bash

# Template validation script for coder/jail development environment

set -e

echo "🔍 Validating Coder template for jail development..."

# Check if we're in the right directory
if [ ! -f "main.tf" ]; then
    echo "❌ Error: main.tf not found. Run this script from the template directory."
    exit 1
fi

echo "✅ Found main.tf"

# Check if cloud-init directory exists
if [ ! -d "cloud-init" ]; then
    echo "❌ Error: cloud-init directory not found."
    exit 1
fi

echo "✅ Found cloud-init directory"

# Check required cloud-init files
if [ ! -f "cloud-init/cloud-config.yaml.tftpl" ]; then
    echo "❌ Error: cloud-config.yaml.tftpl not found."
    exit 1
fi

echo "✅ Found cloud-config.yaml.tftpl"

if [ ! -f "cloud-init/userdata.sh.tftpl" ]; then
    echo "❌ Error: userdata.sh.tftpl not found."
    exit 1
fi

echo "✅ Found userdata.sh.tftpl"

# Check if terraform is available (if running in development environment)
if command -v terraform >/dev/null 2>&1; then
    echo "🔧 Terraform found, validating syntax..."
    
    # Initialize terraform (without remote state)
    terraform init -backend=false >/dev/null 2>&1 || {
        echo "❌ Terraform init failed"
        exit 1
    }
    
    # Validate terraform syntax
    terraform validate >/dev/null 2>&1 || {
        echo "❌ Terraform validation failed"
        terraform validate
        exit 1
    }
    
    echo "✅ Terraform syntax validation passed"
else
    echo "⚠️  Terraform not found, skipping syntax validation"
fi

# Basic syntax checks
echo "🔍 Checking template content..."

# Check that jail-specific packages are included in startup script
if ! grep -q "iptables" main.tf; then
    echo "❌ Error: iptables not found in startup script (required for jail)"
    exit 1
fi

echo "✅ Found iptables installation"

# Check for Go installation
if ! grep -q "golang.org/dl" main.tf; then
    echo "❌ Error: Go installation not found (required for jail development)"
    exit 1
fi

echo "✅ Found Go installation"

# Check for jail repository cloning
if ! grep -q "github.com/coder/jail" main.tf; then
    echo "❌ Error: jail repository cloning not found"
    exit 1
fi

echo "✅ Found jail repository setup"

# Check Ubuntu version (should be 22.04 for better kernel support)
if ! grep -q "ubuntu-jammy-22.04" main.tf; then
    echo "⚠️  Warning: Not using Ubuntu 22.04 LTS (recommended for jail development)"
else
    echo "✅ Using Ubuntu 22.04 LTS"
fi

# Check default instance size (should be at least t3.medium for development)
if grep -q 'default.*=.*"t3.micro"' main.tf; then
    echo "⚠️  Warning: Default instance size is t3.micro, consider t3.medium for better performance"
elif grep -q 'default.*=.*"t3.medium"' main.tf; then
    echo "✅ Default instance size is appropriate for development"
fi

# Check for network configuration
if ! grep -q "net.ipv4.ip_forward" cloud-init/cloud-config.yaml.tftpl; then
    echo "❌ Error: IP forwarding not enabled (required for jail network operations)"
    exit 1
fi

echo "✅ Found network configuration for jail"

echo ""
echo "🎉 Template validation completed successfully!"
echo ""
echo "📋 Summary:"
echo "   - Terraform template: ✅ Valid"
echo "   - Cloud-init files: ✅ Present"
echo "   - Jail dependencies: ✅ Configured"
echo "   - Network settings: ✅ Configured"
echo "   - Go development: ✅ Configured"
echo ""
echo "🚀 Template is ready for use with Coder!"
echo ""
echo "Next steps:"
echo "1. Add this template to your Coder deployment"
echo "2. Configure AWS credentials for your Coder instance"
echo "3. Create a workspace using this template"
echo "4. Start developing jail!"
