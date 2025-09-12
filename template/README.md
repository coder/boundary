---
display_name: Jail Development Environment (AWS EC2)
description: AWS EC2 Linux VM optimized for developing the coder/jail network isolation tool
icon: ../docs/images/logo.png
verified: false
tags: [vm, linux, aws, jail, go, networking, namespaces]
---

# Jail Development Environment on AWS EC2

This Coder template provisions AWS EC2 VMs specifically configured for developing the [coder/jail](https://github.com/coder/jail) network isolation tool. The template sets up a complete development environment with all necessary dependencies, tools, and configurations.

## What is Jail?

Jail is a network isolation tool for monitoring and restricting HTTP/HTTPS requests from processes. It creates isolated network environments for target processes using Linux namespaces and intercepts traffic through a transparent proxy.

## Features

- **Linux VM Environment**: Full Linux VM (not containers) required for namespace syscalls
- **Go 1.24+ Development**: Latest Go toolchain automatically installed
- **Network Tools**: iptables, netfilter, and networking utilities pre-configured 
- **Development Tools**: Build essentials, debugging tools, and utilities
- **Jail Pre-installed**: Repository cloned, built, and ready to use
- **Code Server & JetBrains**: Web-based development environments
- **Network Configuration**: Proper kernel settings for namespace operations

## Prerequisites

### Authentication

By default, this template authenticates to AWS using the provider's default [authentication methods](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#authentication-and-configuration).

The simplest way is via environment variables (e.g. `AWS_ACCESS_KEY_ID`) or a [credentials file](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html#cli-configure-files-format). If you are running Coder on a VM, this file must be in `/home/coder/aws/credentials`.

### Required AWS Permissions

The following sample policy allows Coder to create EC2 instances and modify instances provisioned by Coder:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "VisualEditor0",
      "Effect": "Allow",
      "Action": [
        "ec2:GetDefaultCreditSpecification",
        "ec2:DescribeIamInstanceProfileAssociations",
        "ec2:DescribeTags",
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceTypes",
        "ec2:DescribeInstanceStatus",
        "ec2:CreateTags",
        "ec2:RunInstances",
        "ec2:DescribeInstanceCreditSpecifications",
        "ec2:DescribeImages",
        "ec2:ModifyDefaultCreditSpecification",
        "ec2:DescribeVolumes"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CoderResources",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstanceAttribute",
        "ec2:UnmonitorInstances",
        "ec2:TerminateInstances",
        "ec2:StartInstances",
        "ec2:StopInstances",
        "ec2:DeleteTags",
        "ec2:MonitorInstances",
        "ec2:CreateTags",
        "ec2:RunInstances",
        "ec2:ModifyInstanceAttribute",
        "ec2:ModifyInstanceCreditSpecification"
      ],
      "Resource": "arn:aws:ec2:*:*:instance/*",
      "Condition": {
        "StringEquals": {
          "aws:ResourceTag/Coder_Provisioned": "true"
        }
      }
    }
  ]
}
```

## Architecture

This template provisions the following resources:

- **AWS EC2 Instance**: Ubuntu 22.04 LTS with 20GB storage
- **Network Configuration**: Properly configured for namespace operations
- **Development Environment**: Complete Go development setup
- **Jail Installation**: Pre-built and system-wide accessible

## Software Installed

### Core Development
- **Go 1.24+**: Latest Go compiler and tools
- **Build Tools**: gcc, make, git, and build-essential
- **Jail**: Pre-compiled and installed system-wide

### Network Tools
- **iptables**: Netfilter administration tool
- **iproute2**: Advanced IP routing utilities  
- **tcpdump/wireshark**: Network packet analysis
- **net-tools**: Basic network utilities

### Development Tools
- **Code Server**: Web-based VS Code editor
- **JetBrains**: IDE support for Go development
- **Debug Tools**: gdb, strace, ltrace for troubleshooting
- **System Tools**: htop, tree, jq for system management

## Getting Started

After your workspace is created:

1. **Access your workspace** via Code Server or JetBrains
2. **Navigate to jail directory**: `cd ~/jail`
3. **Build jail**: `make build`
4. **Run tests**: `make test` (requires sudo for E2E tests)
5. **Try jail**: `jail --help`

### Example Usage

```bash
# Test jail with a simple HTTP request
jail --allow "github.com" -- curl https://github.com

# Monitor all network requests
jail --log-level info --allow "*" -- your-application

# Block all requests (default deny-all)
jail -- curl https://example.com  # This will be blocked
```

### Development Workflow

```bash
# Make changes to jail source code
vim ~/jail/jail.go

# Rebuild
make build

# Test your changes
./jail --allow "example.com" -- curl https://example.com

# Run full test suite
sudo make test
```

## Network Namespace Requirements

This template configures the system for network namespace operations:

- **IP Forwarding**: Enabled for network isolation
- **Netfilter**: Configured for traffic interception
- **User Permissions**: Coder user has sudo access for namespace operations
- **Kernel Features**: Modern Ubuntu 22.04 kernel with namespace support

## Instance Sizing

Default instance size is `t3.medium` (2 vCPU, 4GB RAM) which provides adequate resources for jail development. For intensive development or testing, consider `t3.large` or larger.

## Persistent Storage

This template uses persistent EBS storage. Your development work, built binaries, and git history will persist across workspace restarts.

## Security Considerations

- **Sudo Access**: The coder user has passwordless sudo access required for namespace operations
- **Network Tools**: Various network administration tools are installed
- **Kernel Features**: Network forwarding and netfilter capabilities are enabled

This configuration is necessary for jail development but should only be used in trusted environments.

## Troubleshooting

### Jail Binary Not Found
If jail isn't in PATH, it should be at `/usr/local/bin/jail` or you can rebuild:
```bash
cd ~/jail && make build && sudo cp jail /usr/local/bin/
```

### Network Namespace Issues
Ensure you're using sudo for operations that require network namespaces:
```bash
sudo jail --allow "example.com" -- curl https://example.com
```

### Go Module Issues
If Go modules aren't working, ensure GOPATH is set:
```bash
export GOPATH=$HOME/go
export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin
```

## Contributing to Jail

This environment is set up for contributing to the jail project:

1. Make your changes in `~/jail/`
2. Test thoroughly with the test suite
3. Ensure all tests pass: `sudo make test`
4. Submit pull requests to the main jail repository

## Template Customization

This template can be modified to:
- Change instance sizes or storage
- Add additional development tools
- Modify network configurations
- Install different Go versions
- Add custom startup scripts

Edit `main.tf` and the cloud-init templates to customize the environment.
