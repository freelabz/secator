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
