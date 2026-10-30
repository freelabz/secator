#!/bin/bash

echo "Setting up Juice shop ..."
BIN_NAME="docker-compose"
if ! command -v $BIN_NAME 2>&1 > /dev/null; then
	echo "Error: $BIN_NAME not found, trying docker compose"
	BIN_NAME="docker compose"
fi
if ! command -v $BIN_NAME 2>&1 > /dev/null; then
	echo "Error: $BIN_NAME not found"
	exit 1
fi

if [ "$TEST_NO_CLEANUP" != "1" ]; then
	$BIN_NAME pull
	$BIN_NAME up -d
else
	$BIN_NAME up -d --wait --no-recreate
fi

# Seed the local Docker registry with one image so dockerregistrygrabber has a repo to find
# (an empty registry is not reported as a finding). Best-effort; ignore if docker/registry absent.
echo "Seeding local Docker registry ..."
for _ in $(seq 1 20); do
	curl -sf http://127.0.0.1:15000/v2/ >/dev/null 2>&1 && break
	sleep 1
done
if docker pull alpine:latest >/dev/null 2>&1; then
	docker tag alpine:latest 127.0.0.1:15000/testrepo:latest >/dev/null 2>&1
	docker push 127.0.0.1:15000/testrepo:latest >/dev/null 2>&1 || \
		echo "WARN: could not push to local registry (dockerregistrygrabber test will fail)"
else
	echo "WARN: could not pull alpine:latest; local registry left empty (dockerregistrygrabber test will fail)"
fi
