#!/bin/bash

echo "Setting up Juice shop ..."
# Compose v2 is required: `up --wait` blocks until every service with a
# healthcheck reports healthy (readiness probes live in docker-compose.yml).
BIN_NAME="docker compose"
if ! $BIN_NAME version >/dev/null 2>&1; then
	echo "Error: $BIN_NAME (v2) not found"
	exit 1
fi

if [ "$TEST_NO_CLEANUP" != "1" ]; then
	$BIN_NAME pull
	$BIN_NAME up -d --wait --wait-timeout 180 || \
		echo "WARN: some lab services did not become healthy (dependent tests may fail)"
else
	$BIN_NAME up -d --wait --wait-timeout 180 --no-recreate || \
		echo "WARN: some lab services did not become healthy (dependent tests may fail)"
fi

# ---------------------------------------------------------------------------
# Docker Registry (dockerregistrygrabber): seed one repo, then check the
# registry's /v2/_catalog actually lists it. dockerregistrygrabber only reports a
# Vulnerability when the registry answers as an open v2 registry with >=1 repo.
# Seeding can't be a healthcheck (it pushes from the host), so it stays here; the
# registry itself is already healthy at this point.
# ---------------------------------------------------------------------------
echo "Seeding local Docker registry ..."
# Use the locally-cached image when present; only pull when it's missing. This
# keeps the seed working on a warm cache even if Docker Hub is rate-limited or
# unreachable (a bare `docker pull` would fail and skip the seed otherwise).
docker image inspect alpine:latest >/dev/null 2>&1 || docker pull alpine:latest >/dev/null 2>&1
if docker image inspect alpine:latest >/dev/null 2>&1; then
	docker tag alpine:latest 127.0.0.1:15000/testrepo:latest >/dev/null 2>&1
	docker push 127.0.0.1:15000/testrepo:latest >/dev/null 2>&1 || \
		echo "WARN: could not push to local registry (dockerregistrygrabber test will fail)"
	curl -sf http://127.0.0.1:15000/v2/_catalog 2>/dev/null | grep -q '"testrepo"' || \
		echo "WARN: registry catalog does not list 'testrepo' (dockerregistrygrabber test may fail)"
else
	echo "WARN: could not pull alpine:latest; local registry left empty (dockerregistrygrabber test will fail)"
fi
