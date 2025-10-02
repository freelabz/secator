#!/bin/bash

# Define an array of distributions
DISTROS=("alpine" "arch" "debian" "kali" "osx" "ubuntu")
BUILDER=$(which docker || which podman || which buildah)

if [ -z "$BUILDER" ]; then
  echo "Error: No container builder found (docker, podman, or buildah required)"
  exit 1
fi

echo "Using builder: $BUILDER"

mkdir -p .docker/logs/

# Function to build an image
build_image() {
    local DISTRO=$1
    local DOCKERFILE=".docker/Dockerfile.${DISTRO}"
    local STDOUT_LOG=".docker/logs/${DISTRO}.stdout"
    local STDERR_LOG=".docker/logs/${DISTRO}.stderr"
    local IMAGE_NAME="secator-${DISTRO}"

    if [ -f "$DOCKERFILE" ]; then
        echo "🚀 Building $IMAGE_NAME using $DOCKERFILE..."
        $BUILDER build -t "$IMAGE_NAME" -f "$DOCKERFILE" . > $STDOUT_LOG 2> $STDERR_LOG && \
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
