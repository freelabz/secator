"""Per-runner Docker sandbox used by ``run_shell`` in ``--isolated`` mode (also torn down by the
``ai`` task at the end of a run).

Moved verbatim from ``secator/ai/actions.py``.
"""
import os
import re
import threading
from typing import Dict
from secator.ai.actions import ActionContext


# Serializes isolation-container creation within a process: shells in the same run
# share one container, and two racing to create it would collide on the name (125).
_SANDBOX_CREATE_LOCK = threading.Lock()


# --isolated sandbox: resource caps for the per-runner DinD container. The image is resolved
# from config (see _sandbox_image); a base toolset is still auto-installed best-effort at spin-up
# (SECATOR_AI_SANDBOX_PACKAGES) in case the image is bare and the LLM doesn't self-install.
_SANDBOX_MEMORY = os.environ.get("SECATOR_AI_SANDBOX_MEMORY", "1g")


_SANDBOX_PIDS = os.environ.get("SECATOR_AI_SANDBOX_PIDS", "256")


# Docker network for the sandbox. Empty = Docker's default bridge (isolated per
# container). Set SECATOR_AI_SANDBOX_NETWORK=host where the nested-bridge RX path is
# pathologically slow — notably DinD-under-gVisor, whose netstack has no GRO on the
# forwarded path, so downloads into a bridged sandbox crawl (~50 KB/s vs ~50 MB/s on
# the host network). Sandboxes on one DinD already share docker0 (mutually reachable),
# so host networking is a minor isolation change there.
_SANDBOX_NETWORK = os.environ.get("SECATOR_AI_SANDBOX_NETWORK", "")


# Base tools the exploit workflow needs (clone/fetch/run PoCs). Empty string disables auto-install.
_SANDBOX_PACKAGES = os.environ.get("SECATOR_AI_SANDBOX_PACKAGES", "git curl wget python3 python3-pip ca-certificates")


# Package-manager install commands, probed in this order inside the sandbox (the default
# lite image is Alpine -> apk; Debian/Kali -> apt-get; Fedora/RHEL -> dnf/yum).
_PKG_INSTALL_CMDS = {
	"apk": "apk add --no-cache -q {pkgs}",
	# gVisor: libapt ignores gai.conf, so apt needs its own ForceIPv4 (see the bootstrap).
	"apt-get": ("export DEBIAN_FRONTEND=noninteractive && apt-get -o Acquire::ForceIPv4=true update -qq && "
	            "apt-get -o Acquire::ForceIPv4=true install -y -qq --no-install-recommends {pkgs}"),
	"dnf": "dnf install -y -q {pkgs}",
	"yum": "yum install -y -q {pkgs}",
}


# Package names that differ from the Debian name used in SECATOR_AI_SANDBOX_PACKAGES.
_PKG_NAME_MAP = {"apk": {"python3-pip": "py3-pip"}}


def _detect_package_manager(name: str) -> str:
	"""Return the first package manager available in container `name`. Raises when there is
	none, or when the probe itself fails (e.g. the container is not running)."""
	import subprocess
	probe = "for pm in " + " ".join(_PKG_INSTALL_CMDS) + "; do command -v $pm >/dev/null 2>&1 && echo $pm && exit 0; done"
	r = subprocess.run(["docker", "exec", "-u", "0", name, "sh", "-c", probe], capture_output=True, text=True, timeout=30)
	pm = (r.stdout or "").strip()
	if pm in _PKG_INSTALL_CMDS:
		return pm
	if (r.stderr or "").strip():
		raise RuntimeError(r.stderr.strip().splitlines()[-1])
	raise RuntimeError("no supported package manager (apk/apt-get/dnf/yum) in the image")


def _install_base_packages(name: str) -> None:
	"""Best-effort install of _SANDBOX_PACKAGES with the sandbox's own package manager.
	Never raises: a failure only prints a warning (the LLM can still install on demand)."""
	import subprocess
	try:
		pm = _detect_package_manager(name)
		names = _PKG_NAME_MAP.get(pm, {})
		pkgs = " ".join(names.get(pkg, pkg) for pkg in _SANDBOX_PACKAGES.split())
		r = subprocess.run(
			["docker", "exec", "-u", "0", name, "sh", "-c", _PKG_INSTALL_CMDS[pm].format(pkgs=pkgs)],
			capture_output=True, text=True, timeout=300)
		if r.returncode != 0:
			err = (r.stderr or r.stdout or "").strip().splitlines()
			raise RuntimeError(f"{pm} exited {r.returncode}" + (f": {err[-1]}" if err else ""))
	except Exception as e:
		try:
			from secator.output_types import Warning
			from secator.rich import console
			console.print(Warning(message=f"Sandbox {name}: could not install base packages ({_SANDBOX_PACKAGES}): {e}"))
		except Exception:
			pass


def _sandbox_image() -> str:
	"""Resolve the --isolated sandbox image from `addons.ai.isolated_container_image`, replacing
	`{version}` with the running secator version so the sandbox matches the client (default:
	freelabz/secator:<version>-lite, the release-published lite tag). When the setting is still
	the default, the legacy SECATOR_AI_SANDBOX_IMAGE env override is honored for back-compat; an
	explicitly-configured value takes precedence over it."""
	from secator.config import CONFIG
	from secator.definitions import VERSION
	default = 'freelabz/secator:{version}-lite'
	img = CONFIG.addons.ai.isolated_container_image or default
	if img == default:
		img = os.environ.get('SECATOR_AI_SANDBOX_IMAGE', img)
	return img.replace('{version}', VERSION)


def _sandbox_container_name(ctx: "ActionContext", context: Dict) -> str:
	"""Per-RUNNER container name (run_id), not per-session: a subagent may run on another pod's
	dockerd, so it can't share the parent's container. Falls back to session id / 'adhoc'."""
	key = str(context.get("run_id") or getattr(ctx, "session_id", "") or "adhoc")
	return "sbx-" + re.sub(r"[^A-Za-z0-9_.-]", "-", key)[:48]


def _sandbox_is_running(name: str) -> bool:
	"""True iff a container `name` exists and is running."""
	import subprocess
	r = subprocess.run(
		["docker", "inspect", "-f", "{{.State.Running}}", name], capture_output=True, text=True)
	return r.returncode == 0 and r.stdout.strip() == "true"


def _ensure_sandbox_container(ctx: "ActionContext", context: Dict) -> str:
	"""Lazily create the per-runner Kali sandbox container (idempotent via docker inspect).
	Returns the container name. dockerd runs in the pod (DinD); the metadata DROP + egress policy
	are set once in the pod's DinD entrypoint, not here."""
	import subprocess
	name = _sandbox_container_name(ctx, context)
	if _sandbox_is_running(name):
		return name
	# Bind-mount the reports dir into the sandbox at the SAME path so the LLM's clone/build/run
	# in ~/.secator/reports/<ws>/tasks/<n>/.outputs/ works (that path lives on a shared volume the
	# worker + dind both mount; the dind bind resolves it into the nested container). Without this
	# the model's worker-style paths 404 and it wastes a turn `mkdir -p`-ing them.
	from secator.config import CONFIG
	reports_dir = str(CONFIG.dirs.reports)
	created = False
	# Serialize the create: shells in the SAME run share one container, so two arriving
	# before it exists would both `rm` + `run` the same name — the loser's `docker run`
	# fails "name already in use" (exit 125), the intermittent "could not start isolation
	# container". The lock covers only the fast create; the slow gai.conf/apt bootstrap
	# runs outside it so a 5-min install never blocks a shell that just needs the box.
	with _SANDBOX_CREATE_LOCK:
		if not _sandbox_is_running(name):
			subprocess.run(["docker", "rm", "-f", name], capture_output=True)
			run = subprocess.run([
				"docker", "run", "-d", "--name", name,
				"--memory", _SANDBOX_MEMORY, "--pids-limit", _SANDBOX_PIDS,
				*(["--network", _SANDBOX_NETWORK] if _SANDBOX_NETWORK else []),
				"-v", f"{name}:/work", "-v", f"{reports_dir}:{reports_dir}", "-w", "/work",
				# Override the image ENTRYPOINT: the default secator image's is `secator`, which
				# would turn the keep-alive into `secator sleep infinity` and exit at once.
				"--entrypoint", "sleep", _sandbox_image(), "infinity",
			], capture_output=True, text=True)
			if run.returncode != 0:
				# A concurrent creator (another thread on this dockerd) may have won the
				# race — if the container is up now, use it. Otherwise surface docker's
				# real stderr, not a bare "exit status 125".
				if _sandbox_is_running(name):
					return name
				err = (run.stderr or run.stdout or "").strip() or f"docker run exited {run.returncode}"
				raise RuntimeError(err)
			if not _sandbox_is_running(name):
				logs = subprocess.run(
					["docker", "logs", "--tail", "5", name], capture_output=True, text=True, timeout=30)
				out = (logs.stderr or logs.stdout or "").strip()
				raise RuntimeError(f"sandbox container exited right after start{': ' + out if out else ''}")
			created = True
	# Only bootstrap the container WE created (best-effort; a failure must not break the
	# shell path — the LLM can install on demand). Runs as root (`-u 0`): the image's
	# default user may not be (the secator image runs as `secator`).
	if created:
		# gVisor's sandbox network is IPv4-only, but DNS returns AAAA records → every hostname op
		# (git/curl/ssh/pip/apt) tries IPv6 first and HANGS. Prefer IPv4 in glibc via gai.conf (fixes
		# git/curl/ssh/python); apt needs its own ForceIPv4 (libapt ignores gai.conf).
		try:
			subprocess.run(
				["docker", "exec", "-u", "0", name, "sh", "-c",
				 # /work is a fresh volume owned by root; the image's user (the default image
				 # runs as `secator`) must be able to write to it.
				 'chmod 1777 /work; printf "precedence ::ffff:0:0/96 100\\n" > /etc/gai.conf'],
				capture_output=True, timeout=30)
		except Exception:
			pass
		if _SANDBOX_PACKAGES.strip():
			_install_base_packages(name)
	return name


def _teardown_sandbox_container(ctx: "ActionContext", context: Dict) -> None:
	"""Remove the per-runner sandbox container (+ its /work volume). Best-effort; called at AI-task
	end and as orphan cleanup. Safe to call when isolation was never used (no-op)."""
	import subprocess
	name = _sandbox_container_name(ctx, context)
	subprocess.run(["docker", "rm", "-f", "-v", name], capture_output=True)


def _wrap_docker_exec(name: str, command: str) -> str:
	"""Wrap an arbitrary shell command to run inside the sandbox container. base64 round-trip so any
	quoting in `command` survives verbatim (no shell-escaping pitfalls)."""
	import base64
	b64 = base64.b64encode(command.encode()).decode()
	return f"docker exec {name} sh -lc 'echo {b64} | base64 -d | sh'"
