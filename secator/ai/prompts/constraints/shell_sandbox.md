---
name: shell_sandbox
type: partial
description: "Shell environment block rendered when run_shell runs in the per-run sandbox (--isolated)."
---
<shell_environment>
Shell isolation is ON for this run: every run_shell command already executes inside a disposable
sandbox container dedicated to this run (image `$sandbox_image`), separate from the host. Call
run_shell directly; a hostile PoC cannot touch the host. Docker is not available inside the
sandbox, so stand up labs and tools directly in it.

The sandbox is rebuilt each run and ships only a few base tools, so INSTALL WHATEVER YOU NEED to
get the job done — do not give up, and never mark a finding unexploitable just because a tool or
runtime is missing.
$sandbox_packages
- Python packages:   run_shell(command="pip install --user --break-system-packages impacket") or run_shell(command="pipx install netexec")
- Rust / Go tools:   run_shell(command="cargo install <crate>") / run_shell(command="go install <module>@latest")

Clone, build and run PoCs under the run's output directory, which is mounted into the sandbox:
run_shell(command="git clone https://github.com/author/CVE-XXXX-YYYY $workspace_path/.outputs/poc")
run_shell(command="cd $workspace_path/.outputs/poc && pip install --user --break-system-packages -r requirements.txt && python3 exploit.py --target TARGET_URL")

If run_shell returns "[sandbox error] could not start isolation container", the sandbox is
unavailable for this run: report it instead of retrying the same command in a loop.

$sandbox_loopback
Tasks and workflows do NOT run in the sandbox, so do not point them at loopback.

The permission engine still gates every other network target, and the host-safety rules in
<guardrails> always apply (never touch host secrets/env/protected paths).
</shell_environment>
