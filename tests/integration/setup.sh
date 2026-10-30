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

# The PR #1512 service tasks (dockerregistrygrabber / nxc_ftp / nxc_smb) assert a
# specific finding that only appears once the lab service is fully initialised AND
# (for the registry) seeded. `docker compose up -d` only starts the containers; the
# daemons inside need a few more seconds to accept connections, and a bare `sleep`
# is racy under load. So below we poll each service's REAL endpoint until the exact
# precondition the test depends on is observable, then return. Each wait is bounded
# by a timeout and prints a WARN (never blocks the whole suite) if it never settles.

# ---------------------------------------------------------------------------
# Docker Registry (dockerregistrygrabber): seed one repo, then wait until the
# registry's /v2/_catalog actually lists it. dockerregistrygrabber only reports a
# Vulnerability when the registry answers as an open v2 registry with >=1 repo.
# ---------------------------------------------------------------------------
echo "Seeding local Docker registry ..."
# Wait for the registry API to come up.
for _ in $(seq 1 30); do
	curl -sf http://127.0.0.1:15000/v2/ >/dev/null 2>&1 && break
	sleep 1
done
if docker pull alpine:latest >/dev/null 2>&1; then
	docker tag alpine:latest 127.0.0.1:15000/testrepo:latest >/dev/null 2>&1
	docker push 127.0.0.1:15000/testrepo:latest >/dev/null 2>&1 || \
		echo "WARN: could not push to local registry (dockerregistrygrabber test will fail)"
	# Block until the registry serves the seeded repo in its catalog — this is the
	# exact precondition dockerregistrygrabber checks, so once it's true the task is
	# guaranteed a repo (and thus the finding).
	echo "Waiting for registry to serve seeded repo ..."
	for _ in $(seq 1 30); do
		curl -sf http://127.0.0.1:15000/v2/_catalog 2>/dev/null | grep -q '"testrepo"' && break
		sleep 1
	done
	curl -sf http://127.0.0.1:15000/v2/_catalog 2>/dev/null | grep -q '"testrepo"' || \
		echo "WARN: registry catalog does not list 'testrepo' (dockerregistrygrabber test may fail)"
else
	echo "WARN: could not pull alpine:latest; local registry left empty (dockerregistrygrabber test will fail)"
fi

# ---------------------------------------------------------------------------
# vsftpd (nxc_ftp): wait until the FTP control port accepts a connection and the
# server greets with its 220 banner. nxc_ftp only emits the ftp_login_successful
# tag once vsftpd is actually answering logins; a not-yet-ready server produces no
# finding. We probe the banner directly over the TCP control channel.
# ---------------------------------------------------------------------------
echo "Waiting for FTP (vsftpd) to be ready ..."
ftp_ready=0
for _ in $(seq 1 30); do
	# Read the FTP greeting; vsftpd answers "220 ...". Use bash's /dev/tcp so we
	# don't depend on nc/curl being present. Timeout each attempt so a hung
	# connection can't stall the loop.
	banner=$(timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/10021 && head -n 1 <&3' 2>/dev/null)
	case "$banner" in
		220*) ftp_ready=1; break ;;
	esac
	sleep 1
done
[ "$ftp_ready" = 1 ] || echo "WARN: FTP server never returned a 220 banner on :10021 (nxc_ftp test may fail)"

# ---------------------------------------------------------------------------
# Samba (nxc_smb): wait until the server is fully initialised the way nxc sees it —
# i.e. a null-session SMB scan reports the host-info line with "Null Auth:True" AND
# enumerates shares. Samba (dperson/samba) needs several seconds after the container
# starts before it answers null sessions; until then nxc only gets a partial reply
# and the expected Null-Auth / unauth-share Vulnerabilities are missing. Poll with
# the real tool so readiness == the exact condition the test asserts.
# ---------------------------------------------------------------------------
if command -v nxc >/dev/null 2>&1; then
	echo "Waiting for Samba (SMB null session) to be ready ..."
	smb_ready=0
	for _ in $(seq 1 30); do
		out=$(timeout 30 nxc smb 127.0.0.1 --port 10445 -u '' -p '' --shares 2>&1)
		# Require both markers: the Null-Auth host-info line and at least one
		# enumerated share — these back the two asserted Vulnerabilities.
		if echo "$out" | grep -qi 'Null Auth:True' && echo "$out" | grep -q 'Enumerated shares'; then
			smb_ready=1
			break
		fi
		sleep 2
	done
	[ "$smb_ready" = 1 ] || echo "WARN: Samba null session / share enumeration not ready on :10445 (nxc_smb test may fail)"
else
	echo "WARN: nxc not installed; skipping Samba readiness wait (nxc_smb test may fail)"
fi
