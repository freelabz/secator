#!/bin/bash
# Script to build Debian source package for PPA upload
# Usage: ./scripts/build_ppa.sh [ubuntu_release]
#   ubuntu_release: focal, jammy, noble (default: focal)

set -e

UBUNTU_RELEASE=${1:-focal}
VERSION=$(grep '^version' pyproject.toml | head -1 | cut -d'"' -f2)
PACKAGE_VERSION="${VERSION}-1ppa1~${UBUNTU_RELEASE}"

echo "Building secator ${PACKAGE_VERSION} for Ubuntu ${UBUNTU_RELEASE}"

# Check if required tools are installed
for cmd in debuild dput; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: $cmd is not installed"
        echo "Please install: sudo apt-get install devscripts build-essential"
        exit 1
    fi
done

# Update changelog with the Ubuntu release
cp debian/changelog debian/changelog.bak
sed -i "s/focal/${UBUNTU_RELEASE}/g" debian/changelog
sed -i "s/^secator (.*)/secator (${PACKAGE_VERSION})/" debian/changelog

# Build the source package
echo "Building source package..."
debuild -S -sa -d

# Restore original changelog
mv debian/changelog.bak debian/changelog

echo ""
echo "✓ Source package built successfully!"
echo ""
echo "Package files created in parent directory:"
echo "  - secator_${PACKAGE_VERSION}.dsc"
echo "  - secator_${PACKAGE_VERSION}_source.changes"
echo "  - secator_${PACKAGE_VERSION}.debian.tar.xz"
echo ""
echo "To upload to PPA, run:"
echo "  dput ppa:freelabz/secator ../secator_${PACKAGE_VERSION}_source.changes"
echo ""
echo "To test locally with pbuilder:"
echo "  sudo pbuilder build ../secator_${PACKAGE_VERSION}.dsc"
echo ""
