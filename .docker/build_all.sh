#!/bin/bash

# Define an array of distributions
DISTROS=("alpine" "arch" "debian" "kali" "osx" "ubuntu")

# Function to build an image
build_image() {
    local DISTRO=$1
    local DOCKERFILE=".docker/Dockerfile.${DISTRO}"
    local IMAGE_NAME="secator-${DISTRO}"

    if [ -f "$DOCKERFILE" ]; then
        echo "🚀 Building $IMAGE_NAME using $DOCKERFILE..."
        docker build -t "$IMAGE_NAME" -f "$DOCKERFILE" . && \
        echo "✅ Successfully built $IMAGE_NAME" || \
        echo "❌ Failed to build $IMAGE_NAME"
    else
        echo "⚠️ Dockerfile $DOCKERFILE not found, skipping..."
    fi
}

# Iterate through the distributions and build in parallel
for DISTRO in "${DISTROS[@]}"; do
    build_image "$DISTRO" &
done

# Wait for all background jobs to finish
wait

echo "🎉 All parallel builds completed!"
