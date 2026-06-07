#!/bin/bash

echo "Tearing down Juice shop ..."
BIN_NAME="docker compose"
if ! command -v $BIN_NAME 2>&1 > /dev/null; then
	echo "Error: $BIN_NAME not found, trying docker-compose"
	BIN_NAME="docker-compose"
fi
if ! command -v $BIN_NAME 2>&1 > /dev/null; then
	echo "Error: $BIN_NAME not found"
	exit 1
fi

if [ "$TEST_NO_CLEANUP" = "1" ]; then
	echo "Aborting cleanup since TEST_NO_CLEANUP is set"
	exit 0
fi
$BIN_NAME down -v
