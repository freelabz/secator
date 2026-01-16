#!/bin/bash
# Quick test script for install_universal.sh in Docker containers

# Usage examples:
# ./test_install_docker.sh ubuntu
# ./test_install_docker.sh debian
# ./test_install_docker.sh alpine
# ./test_install_docker.sh arch
# ./test_install_docker.sh fedora

DISTRO=${1:-ubuntu}

case $DISTRO in
    ubuntu)
        IMAGE="ubuntu:latest"
        ;;
    debian)
        IMAGE="debian:latest"
        ;;
    alpine)
        IMAGE="alpine:latest"
        ;;
    arch)
        IMAGE="archlinux:latest"
        ;;
    fedora)
        IMAGE="fedora:latest"
        ;;
    *)
        echo "Unknown distribution: $DISTRO"
        echo "Supported: ubuntu, debian, alpine, arch, fedora"
        exit 1
        ;;
esac

echo "Testing secator installation in $IMAGE..."
echo ""

# Use the script from GitHub (or local path)
SCRIPT_URL="https://raw.githubusercontent.com/freelabz/secator/main/scripts/install_universal.sh"

# For local testing, you can also use:
# docker run -it --rm -v $(pwd)/scripts:/scripts $IMAGE bash -c "bash /scripts/install_universal.sh"

docker run -it --rm $IMAGE bash -c "
    # Install curl first (needed to download the script)
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq && apt-get install -y -qq curl
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache curl
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm curl
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y curl
    elif command -v yum >/dev/null 2>&1; then
        yum install -y curl
    fi
    
    # Run the installation script
    /bin/bash -c \"\$(curl -fsSL $SCRIPT_URL)\"
    
    # Test that secator works
    echo ''
    echo '=== Testing secator installation ==='
    secator --help
"

