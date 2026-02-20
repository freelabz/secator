# AI Attack Mode Library Execution Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace CLI command execution in attack mode with structured JSON responses executed via Python bindings (Task, Workflow, Scan runners).

**Architecture:** Update attack mode system prompt to instruct JSON format with `type` field, add `_execute_secator_runner()` method to handle task/workflow/scan execution via Python bindings, add option validation using `get_config_options()`, and keep shell fallback for curl/wget/nmap.

**Tech Stack:** Python, secator runners (Task, Workflow, Scan), TemplateLoader, get_config_options

---

### Task 1: Add SECATOR_LIBRARY_REFERENCE Constant

**Files:**
- Modify: `secator/tasks/ai.py:339-387` (after SECATOR_CHEATSHEET)

**Step 1: Add the library reference constant**

Add after `SECATOR_CHEATSHEET` constant (around line 387):

```python
SECATOR_LIBRARY_REFERENCE = """
=== SECATOR RUNNERS ===

RUNNER TYPES:
- task: Single tool execution (httpx, nmap, nuclei, ffuf, katana, subfinder, etc.)
- workflow: Multi-task pipelines (host_recon, url_crawl, subdomain_recon, etc.)
- scan: Comprehensive scans (host, domain, url, network, subdomain)

AVAILABLE TASKS:
httpx, nmap, nuclei, ffuf, katana, subfinder, dnsx, feroxbuster, gospider,
dalfox, arjun, gau, waybackurls, cariddi, grype, gitleaks, semgrep, trufflehog

AVAILABLE WORKFLOWS:
host_recon, subdomain_recon, url_crawl, url_fuzz, url_vuln, url_dirsearch,
domain_recon, code_scan, cidr_recon, url_bypass, url_secrets_hunt

AVAILABLE SCANS:
host, domain, url, network, subdomain

COMMON OPTIONS:
rate_limit, timeout, delay, proxy, threads, follow_redirect, header, output_path

REFERENCE (verify options exist before using):
Tasks: https://github.com/freelabz/secator/tree/main/secator/tasks
Configs: https://github.com/freelabz/secator/tree/main/secator/configs
"""
```

**Step 2: Verify syntax**

Run: `python -m py_compile secator/tasks/ai.py`
Expected: No output (success)

**Step 3: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "feat(ai): add SECATOR_LIBRARY_REFERENCE constant for attack mode"
```

---

### Task 2: Update Attack Mode System Prompt

**Files:**
- Modify: `secator/tasks/ai.py` - `SYSTEM_PROMPTS["attack"]`

**Step 1: Replace the attack prompt**

Replace the current `"attack"` entry in `SYSTEM_PROMPTS` with:

```python
    "attack": f"""You are an autonomous penetration testing agent conducting authorized security testing.

Your mission is to:
1. Analyze the current findings and identify exploitable vulnerabilities
2. Plan attack sequences to validate vulnerabilities
3. Execute attacks using available secator runners or shell commands
4. Validate successful exploits with proof-of-concept
5. Document findings with reproduction steps

{SECATOR_LIBRARY_REFERENCE}

IMPORTANT RULES:
- ALWAYS prefer secator runners (task/workflow/scan) over shell commands
- Only test targets explicitly provided as inputs
- Document every action taken
- Stop if you encounter out-of-scope systems
- Provide clear proof for each validated vulnerability
- Only use options that exist for the runner (check reference if unsure)

For secator execution, respond with JSON:
{{
    "action": "execute",
    "type": "task|workflow|scan",
    "name": "runner_name",
    "targets": ["target1", "target2"],
    "opts": {{"rate_limit": 100}},
    "reasoning": "why this action",
    "expected_outcome": "what we expect to find"
}}

For shell commands (curl, wget, nmap direct), respond with JSON:
{{
    "action": "execute",
    "type": "shell",
    "command": "curl -s http://example.com",
    "target": "example.com",
    "reasoning": "why this action",
    "expected_outcome": "what we expect to find"
}}

When validating a vulnerability, respond with:
{{
    "action": "validate",
    "vulnerability": "name",
    "target": "target url or host",
    "proof": "evidence of exploitation",
    "severity": "critical|high|medium|low|info",
    "reproduction_steps": ["step1", "step2", ...]
}}

When done, respond with:
{{"action": "complete", "summary": "overall findings"}}""",
```

**Step 2: Verify syntax**

Run: `python -m py_compile secator/tasks/ai.py`
Expected: No output (success)

**Step 3: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "feat(ai): update attack mode prompt for library execution"
```

---

### Task 3: Add _validate_runner_opts Method

**Files:**
- Modify: `secator/tasks/ai.py` - add method to `ai` class

**Step 1: Add the validation method**

Add after `_get_secator_help()` method (around line 1168):

```python
    def _validate_runner_opts(
        self, runner_type: str, name: str, opts: Dict
    ) -> tuple[Dict, List[str], List[str]]:
        """Validate options for a secator runner.

        Returns:
            Tuple of (valid_opts, invalid_opt_names, valid_opt_names)
        """
        from secator.template import TemplateLoader, get_config_options

        try:
            # Load config based on runner type
            if runner_type == "task":
                config = TemplateLoader(input={"name": name, "type": "task"})
            else:
                config = TemplateLoader(name=f"{runner_type}s/{name}")

            # Get valid options
            config_opts = get_config_options(config)
            valid_opt_names = [s.replace("-", "_") for s in config_opts.keys()]

            # Separate valid and invalid options
            valid_opts = {}
            invalid_opts = []
            for key, value in opts.items():
                normalized_key = key.replace("-", "_")
                if normalized_key in valid_opt_names:
                    valid_opts[normalized_key] = value
                else:
                    invalid_opts.append(key)

            return valid_opts, invalid_opts, valid_opt_names
        except Exception as e:
            logger.warning(f"Failed to validate options for {runner_type}/{name}: {e}")
            return opts, [], []
```

**Step 2: Verify syntax**

Run: `python -m py_compile secator/tasks/ai.py`
Expected: No output (success)

**Step 3: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "feat(ai): add _validate_runner_opts method"
```

---

### Task 4: Add _execute_secator_runner Method

**Files:**
- Modify: `secator/tasks/ai.py` - add method to `ai` class

**Step 1: Add the runner execution method**

Add after `_validate_runner_opts()` method:

```python
    def _execute_secator_runner(
        self, runner_type: str, name: str, targets: List[str], opts: Dict
    ) -> Generator:
        """Execute a secator runner (task, workflow, or scan) and yield results.

        Args:
            runner_type: One of 'task', 'workflow', 'scan'
            name: Name of the runner (e.g., 'httpx', 'host_recon', 'host')
            targets: List of targets to run against
            opts: Options to pass to the runner

        Yields:
            Results from the runner execution
        """
        from secator.runners import Task, Workflow, Scan
        from secator.template import TemplateLoader

        # Set minimal options for running embedded
        run_opts = {
            "print_item": False,
            "print_line": False,
            "print_cmd": False,
            "print_progress": False,
            "print_start": False,
            "print_end": False,
            "print_target": False,
            "sync": True,
            **opts,
        }

        try:
            if runner_type == "task":
                config = TemplateLoader(input={"name": name, "type": "task"})
                runner = Task(config, inputs=targets, run_opts=run_opts)
            elif runner_type == "workflow":
                config = TemplateLoader(name=f"workflows/{name}")
                runner = Workflow(config, inputs=targets, run_opts=run_opts)
            elif runner_type == "scan":
                config = TemplateLoader(name=f"scans/{name}")
                runner = Scan(config, inputs=targets, run_opts=run_opts)
            else:
                yield Error(message=f"Unknown runner type: {runner_type}")
                return

            # Yield all results from the runner
            result_count = 0
            for result in runner:
                result_count += 1
                yield result

            yield Info(message=f"{runner_type.capitalize()} '{name}' completed with {result_count} results")

        except Exception as e:
            yield Error(message=f"Failed to execute {runner_type} '{name}': {str(e)}")
```

**Step 2: Verify syntax**

Run: `python -m py_compile secator/tasks/ai.py`
Expected: No output (success)

**Step 3: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "feat(ai): add _execute_secator_runner method"
```

---

### Task 5: Update _mode_attack Execute Handler

**Files:**
- Modify: `secator/tasks/ai.py` - `_mode_attack()` method, execute action block

**Step 1: Find and replace the execute action handler**

Find the block starting with `elif action_type == "execute":` (around line 930) and replace the entire block up to `elif action_type == "validate":` with:

```python
                elif action_type == "execute":
                    exec_type = action.get("type", "shell")

                    # Handle secator runners (task, workflow, scan)
                    if exec_type in ("task", "workflow", "scan"):
                        name = action.get("name", "")
                        action_targets = action.get("targets", []) or targets
                        opts = action.get("opts", {})

                        # Scope check - all targets must be in scope
                        out_of_scope = [t for t in action_targets if not self._is_in_scope(t, targets)]
                        if out_of_scope:
                            yield Warning(message=f"Targets out of scope: {out_of_scope}")
                            encrypted_context = json.dumps(attack_context)
                            if sensitive:
                                encrypted_context = encryptor.encrypt(encrypted_context)
                            prompt = f"Targets {out_of_scope} are out of scope. Only test: {targets_str}. Choose another action.\n\nContext:\n{encrypted_context}"
                            continue

                        # Validate options
                        valid_opts, invalid_opts, valid_opt_names = self._validate_runner_opts(
                            exec_type, name, opts
                        )

                        if invalid_opts:
                            yield Warning(message=f"Invalid options for {exec_type} '{name}': {invalid_opts}")
                            encrypted_context = json.dumps(attack_context)
                            if sensitive:
                                encrypted_context = encryptor.encrypt(encrypted_context)
                            prompt = f"""Invalid options for {exec_type} '{name}': {invalid_opts}

Valid options are: {valid_opt_names}

Please retry with valid options only.

Context:
{encrypted_context}"""
                            continue

                        yield Info(message=f"[CMD] secator {exec_type[0]} {name} {' '.join(action_targets)}")

                        if dry_run:
                            yield Tag(
                                name="dry_run_runner",
                                value=f"{exec_type}/{name}",
                                match=", ".join(action_targets),
                                category="attack",
                                extra_data={
                                    "reasoning": action.get("reasoning", ""),
                                    "opts": valid_opts,
                                },
                            )
                            result_output = f"[DRY RUN] {exec_type.capitalize()} '{name}' not executed"
                            runner_results = []
                        else:
                            # Execute the runner and collect results
                            runner_results = []
                            for result in self._execute_secator_runner(
                                exec_type, name, action_targets, valid_opts
                            ):
                                runner_results.append(result)
                                yield result

                            # Format results for LLM context
                            result_output = format_results_for_llm(runner_results, max_items=50)

                        if verbose:
                            yield Info(message=f"[OUTPUT] {_truncate(result_output)}")

                        attack_context["successful_attacks"].append({
                            "type": exec_type,
                            "name": name,
                            "targets": action_targets,
                            "result_count": len(runner_results),
                            "output": result_output[:2000],
                        })

                        # Build next prompt
                        encrypted_output = result_output[:4000]
                        encrypted_context = json.dumps(attack_context)
                        if sensitive:
                            encrypted_output = encryptor.encrypt(encrypted_output)
                            encrypted_context = encryptor.encrypt(encrypted_context)

                        prompt = f"""{exec_type.capitalize()} '{name}' executed on {action_targets}.

Results:
{encrypted_output}

Previous context:
{encrypted_context}

Analyze the results and decide next action (execute, validate, or complete)."""

                    # Handle shell commands (curl, wget, nmap direct)
                    elif exec_type == "shell":
                        command = action.get("command", "")
                        target = action.get("target", "")

                        # Scope check
                        if target and not self._is_in_scope(target, targets):
                            yield Warning(message=f"Target {target} is out of scope, skipping")
                            encrypted_context = json.dumps(attack_context)
                            if sensitive:
                                encrypted_context = encryptor.encrypt(encrypted_context)
                            prompt = f"Target {target} was out of scope. Only test: {targets_str}. Choose another action.\n\nContext:\n{encrypted_context}"
                            continue

                        yield Info(message=f"[CMD] {command}")

                        if dry_run:
                            yield Tag(
                                name="dry_run_command",
                                value=command,
                                match=target,
                                category="attack",
                                extra_data={"reasoning": action.get("reasoning", "")},
                            )
                            result_output = "[DRY RUN] Command not executed"
                        else:
                            result_output = self._execute_command(command)

                        if verbose:
                            yield Info(message=f"[OUTPUT] {_truncate(result_output)}")

                        attack_context["successful_attacks"].append({
                            "type": "shell",
                            "command": command,
                            "target": target,
                            "output": result_output[:2000],
                        })

                        # Encrypt for next prompt
                        encrypted_output = result_output[:4000]
                        encrypted_command = command
                        encrypted_context = json.dumps(attack_context)
                        if sensitive:
                            encrypted_output = encryptor.encrypt(encrypted_output)
                            encrypted_command = encryptor.encrypt(encrypted_command)
                            encrypted_context = encryptor.encrypt(encrypted_context)

                        prompt = f"""Shell command executed:
{encrypted_command}

Output:
{encrypted_output}

Previous context:
{encrypted_context}

Analyze the output and decide next action (execute, validate, or complete)."""

                    else:
                        yield Warning(message=f"Unknown execute type: {exec_type}")
                        prompt = f"Unknown execute type '{exec_type}'. Use: task, workflow, scan, or shell."
                        continue

```

**Step 2: Verify syntax**

Run: `python -m py_compile secator/tasks/ai.py`
Expected: No output (success)

**Step 3: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "feat(ai): update attack mode execute handler for library execution"
```

---

### Task 6: Manual Test

**Step 1: Test dry-run with task type**

Run:
```bash
source .venv/bin/activate
secator x ai testphp.vulnweb.com --mode attack --dry-run --verbose --model gpt-4o-mini
```

Expected: See JSON actions with `type: task/workflow/scan` format instead of CLI commands

**Step 2: Test actual execution (optional)**

Run:
```bash
secator x ai testphp.vulnweb.com --mode attack --max-iterations 3 --model gpt-4o-mini
```

Expected: Tasks execute via Python bindings and yield results properly

**Step 3: Final commit if any fixes needed**

```bash
git add secator/tasks/ai.py
git commit -m "fix(ai): library mode adjustments"
```

---

### Task 7: Update Imports

**Files:**
- Modify: `secator/tasks/ai.py` - imports at top of file

**Step 1: Verify imports are present**

Ensure these imports exist at the top of the file (most should already be there):

```python
from typing import Any, Dict, Generator, List, Optional
```

The runner imports (Task, Workflow, Scan, TemplateLoader, get_config_options) are done inside the methods to avoid circular imports.

**Step 2: Verify the file compiles**

Run: `python -m py_compile secator/tasks/ai.py`
Expected: No output (success)

**Step 3: Commit if changes made**

```bash
git add secator/tasks/ai.py
git commit -m "chore(ai): verify imports for library mode"
```
