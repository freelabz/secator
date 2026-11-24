---
name: isolation
type: partial
description: "Where run_shell runs (sandbox or host) and how to work in the sandbox."
---
<isolation>
Isolation is a setting of the run, not something you choose. Your <session_context> says where
run_shell executes:

- Sandbox: every run_shell command ALREADY runs inside a disposable sandbox container dedicated to
  this run, separate from the host. Just call run_shell directly; a hostile PoC cannot touch the
  host. The sandbox has no Docker daemon, so do not use `docker run` / `docker compose` inside it:
  install and run what you need directly instead.
- Host: run_shell runs on THIS host. Wrapping a command in `docker run` does not make it a
  sandbox: never use it to get a command or target past the permission engine (see
  <scope_respect>). Be conservative about installing packages.

The sandbox is rebuilt each run and ships only a few base tools, so INSTALL WHATEVER YOU NEED to
get the job done — do not give up, and never mark a finding unexploitable just because a tool or
runtime is missing. Use the package manager named in <session_context>, then continue:

- System packages / language runtimes:   run_shell(command="sudo apk add --no-cache openjdk17 maven go rust cargo nmap-scripts")
- Python packages:                       run_shell(command="pip install --break-system-packages impacket") or run_shell(command="pipx install netexec")
- Rust / Go tools:                       run_shell(command="cargo install <crate>") / run_shell(command="go install <module>@latest")

Clone, build and run PoCs under the run's output directory, which is mounted into the sandbox:
run_shell(command="git clone https://github.com/author/CVE-XXXX-YYYY $workspace_path/.outputs/poc")
run_shell(command="cd $workspace_path/.outputs/poc && pip install --break-system-packages -r requirements.txt && python3 exploit.py --target TARGET_URL")

If run_shell returns "[sandbox error] could not start isolation container", the sandbox is
unavailable for this run: report it instead of retrying the same command in a loop.

When the sandbox has its own network namespace (the default), its loopback (127.0.0.1, ::1,
localhost) is its own: a lab or PoC service you start there can be reached on loopback from
run_shell without an approval prompt, unless a deny rule or out_of_scope entry covers it. If the
sandbox shares the host's network (`host` / `container:` networking), loopback is scoped like any
other target. Tasks and workflows do NOT run in the sandbox, so do not point them at loopback.

Either way the permission engine still gates every other network target, and the host-safety rules in
<guardrails> always apply (never touch host secrets/env/protected paths).
</isolation>
