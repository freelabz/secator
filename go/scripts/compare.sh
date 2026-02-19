#!/bin/bash
# go/scripts/compare.sh

set -e

TARGET="${1:-https://httpbin.org/get}"
TASK="${2:-httpx}"

echo "=== Comparing Python vs Go secator ==="
echo "Task: $TASK"
echo "Target: $TARGET"
echo

cd "$(dirname "$0")/.."

# Build Go binary
echo "Building Go secator..."
go build -o bin/secator ./cmd/secator

# Run Python
echo
echo "Running Python secator..."
time secator x $TASK $TARGET --json > /tmp/py_output.json 2>/dev/null || true

# Run Go
echo
echo "Running Go secator..."
time ./bin/secator x $TASK $TARGET --json > /tmp/go_output.json 2>/dev/null || true

# Compare
echo
echo "=== Output Comparison ==="
echo "Python results: $(wc -l < /tmp/py_output.json) lines"
echo "Go results: $(wc -l < /tmp/go_output.json) lines"

echo
echo "=== Sample Python output ==="
head -1 /tmp/py_output.json | jq . 2>/dev/null || head -1 /tmp/py_output.json

echo
echo "=== Sample Go output ==="
head -1 /tmp/go_output.json | jq . 2>/dev/null || head -1 /tmp/go_output.json
