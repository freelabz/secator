---
name: shell_host
type: partial
description: "Shell environment block rendered when run_shell runs on the host (no --isolated)."
---
<shell_environment>
Shell isolation is OFF for this run: run_shell executes directly on THIS host, not in a sandbox.
<session_context> (when present) lists the host OS, package manager and sudo availability.

- Be conservative about changing the host: install only what the task needs, preferably
  user-level (pipx, `pip install --user`, `go install`, `cargo install`), and keep clones, builds
  and PoCs under $runner_dir/.outputs/.
- Java tools: check `java -version` first; install a headless JRE with the host package manager
  only if none is present and the task needs it, then run the tool with `java -jar <tool>.jar`.
- If the host has a working Docker daemon (`docker info` succeeds), you may use it to stand up a
  local lab (e.g. an official vulnerable image bound to 127.0.0.1). Docker commands are not
  inspected for targets, so use them only for such local labs, never to run a command or reach a
  target that would otherwise be checked or denied.
- Loopback (127.0.0.1, ::1, localhost) is this host's: it is scoped like any other target.

The permission engine gates every network target, and the host-safety rules in <guardrails>
always apply (never touch host secrets/env/protected paths).
</shell_environment>
