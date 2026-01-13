# PPA Package Setup and Maintenance

This document describes how the Secator PPA (Personal Package Archive) is set up and how to maintain it.

## Overview

Secator can be installed on Ubuntu systems via a custom PPA. This provides an easy installation method using the standard APT package manager:

```bash
sudo add-apt-repository ppa:freelabz/secator
sudo apt update
sudo apt install secator
```

## Supported Ubuntu Releases

The PPA supports the following Ubuntu releases:
- Ubuntu 20.04 LTS (Focal Fossa)
- Ubuntu 22.04 LTS (Jammy Jellyfish)
- Ubuntu 24.04 LTS (Noble Numbat)

## Prerequisites for PPA Maintenance

### 1. Launchpad Account Setup

1. Create a Launchpad account at https://launchpad.net/
2. Create a PPA at https://launchpad.net/~/+activate-ppa
   - Name: `secator`
   - Display name: `Secator - The pentester's swiss knife`
   - Description: `Security assessment task and workflow runner`

### 2. GPG Key Setup

Generate and configure a GPG key for signing packages:

```bash
# Generate a new GPG key
gpg --full-generate-key
# Choose RSA and RSA, 4096 bits, no expiration

# List your keys
gpg --list-keys

# Upload your public key to Ubuntu keyserver
gpg --keyserver keyserver.ubuntu.com --send-keys YOUR_KEY_ID

# Export private key for GitHub Secrets (if using CI/CD)
gpg --export-secret-keys YOUR_KEY_ID | base64
```

### 3. Sign Ubuntu Code of Conduct

Sign the Ubuntu Code of Conduct at https://launchpad.net/codeofconduct

## Building Packages Locally

Use the provided script to build source packages:

```bash
# Build for Ubuntu 20.04 (Focal)
./scripts/build_ppa.sh focal

# Build for Ubuntu 22.04 (Jammy)
./scripts/build_ppa.sh jammy

# Build for Ubuntu 24.04 (Noble)
./scripts/build_ppa.sh noble
```

## Uploading to PPA

### Configure dput

Create or edit `~/.dput.cf`:

```ini
[ppa:freelabz/secator]
fqdn = ppa.launchpad.net
method = ftp
incoming = ~freelabz/ubuntu/secator/
login = anonymous
allow_unsigned_uploads = 0
```

### Upload Package

```bash
# Upload the source package
dput ppa:freelabz/secator ../secator_VERSION_source.changes
```

## Automated Builds via GitHub Actions

The PPA packages are automatically built and uploaded when a new version tag is pushed:

1. Tag a new release: `git tag v0.24.0`
2. Push the tag: `git push origin v0.24.0`
3. GitHub Actions workflow (`.github/workflows/ppa.yml`) will:
   - Build source packages for all supported Ubuntu releases
   - Sign packages with GPG key
   - Upload to Launchpad PPA
   - Launchpad will build binary packages for different architectures

### Required GitHub Secrets

Configure these secrets in GitHub repository settings:

- `PPA_GPG_PRIVATE_KEY`: Base64-encoded GPG private key
- `PPA_GPG_PASSPHRASE`: Passphrase for the GPG key

## Package Files

The Debian packaging files are located in the `debian/` directory:

- `debian/control`: Package metadata and dependencies
- `debian/changelog`: Version history and release notes
- `debian/rules`: Build instructions
- `debian/compat`: Debhelper compatibility level
- `debian/source/format`: Source package format

## Testing Packages

### Local Testing with pbuilder

```bash
# Install pbuilder
sudo apt-get install pbuilder

# Create a base environment
sudo pbuilder create --distribution focal

# Build and test the package
sudo pbuilder build ../secator_VERSION.dsc
```

### Testing Installed Package

After building, you can install and test:

```bash
sudo dpkg -i secator_VERSION_all.deb
secator --version
secator --help
```

## Updating Package Dependencies

When Python dependencies change in `pyproject.toml`, update `debian/control`:

1. Map Python packages to Debian package names (usually `python3-<package>`)
2. Add to the `Depends:` field in `debian/control`
3. Test the build to ensure all dependencies are satisfied

## Common Issues

### Missing Dependencies

If a Python dependency doesn't have a Debian package:
- Check if it's available in Ubuntu repositories
- Consider bundling the dependency or requesting it be added to Ubuntu

### Build Failures

Check Launchpad build logs at:
https://launchpad.net/~freelabz/+archive/ubuntu/secator/+packages

### GPG Signing Issues

Ensure your GPG key is:
- Uploaded to Ubuntu keyserver
- Associated with your Launchpad account
- Not expired

## Version Numbering

PPA packages use the format: `VERSION-1ppa1~RELEASE`

Example: `0.24.0-1ppa1~focal`
- `0.24.0`: Upstream version
- `1`: Debian revision
- `ppa1`: PPA revision
- `~focal`: Ubuntu release (tilde ensures proper upgrade path)

## Resources

- [Launchpad PPA Documentation](https://help.launchpad.net/Packaging/PPA)
- [Ubuntu Packaging Guide](https://packaging.ubuntu.com/)
- [Debian Python Policy](https://www.debian.org/doc/packaging-manuals/python-policy/)
