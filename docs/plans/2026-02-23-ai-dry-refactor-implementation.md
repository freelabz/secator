# AI Task DRY Refactor - Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Refactor `secator/tasks/ai.py` from ~3343 lines to ~2000 lines by DRYing out repeated patterns, unifying mode handlers, and creating an extensible action dispatch system.

**Architecture:** Conservative single-file refactor using handler pattern with registry dispatch, unified mode configuration, dataclasses for context/results, and consolidated prompts. Maintains all existing functionality.

**Tech Stack:** Python 3.10+, dataclasses, typing, Generator patterns

---

## Task 1: Add Data Structures (ActionResult, ActionContext)

**Files:**
- Modify: `secator/tasks/ai.py:1-25` (imports section)

**Step 1: Add dataclass imports and define ActionResult**

Add after line 11 (after `from dataclasses import asdict`):

```python
from dataclasses import dataclass, asdict, field
```

Add after the `SensitiveDataEncryptor` class (around line 1341), before the helper functions:

```python
# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class ActionResult:
    """Result of executing an action."""
    success: bool
    output: str
    errors: list = field(default_factory=list)
    results: list = field(default_factory=list)  # OutputType instances
    context_update: dict = field(default_factory=dict)  # What to add to attack_context


@dataclass
class ActionContext:
    """Shared context for action execution."""
    targets: list
    model: str
    api_base: str = None
    temperature: float = 0.7
    encryptor: 'SensitiveDataEncryptor' = None
    sensitive: bool = True
    dry_run: bool = False
    verbose: bool = False
    dangerous: bool = False
    disable_secator: bool = False
    max_iterations: int = 10
    attack_context: dict = field(default_factory=dict)
    custom_prompt_suffix: str = ""
    auto_yes: bool = False
    in_ci: bool = False
```

**Step 2: Verify the file still parses**

Run: `python -c "import secator.tasks.ai; print('OK')"`
Expected: OK

**Step 3: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "$(cat <<'EOF'
refactor(ai): add ActionResult and ActionContext dataclasses

Phase 1 of DRY refactor - add data structures for unified action handling.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Add Action Handler Registry

**Files:**
- Modify: `secator/tasks/ai.py` (after ActionContext class)

**Step 1: Add ACTION_HANDLERS registry**

Add after `ActionContext` class:

```python
# =============================================================================
# ACTION HANDLER REGISTRY
# =============================================================================

ACTION_HANDLERS = {
    "execute": "_handle_execute",
    "validate": "_handle_validate",
    "complete": "_handle_complete",
    "stop": "_handle_stop",
    "report": "_handle_report",
    # Phase 2 placeholders (not implemented yet):
    # "query": "_handle_query",
    # "output_type": "_handle_output_type",
    # "prompt": "_handle_prompt",
}
```

**Step 2: Verify the file still parses**

Run: `python -c "import secator.tasks.ai; print('OK')"`
Expected: OK

**Step 3: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "$(cat <<'EOF'
refactor(ai): add ACTION_HANDLERS registry

Dispatcher lookup table for action types. Enables adding new actions by
registering handler method names.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Add MODE_CONFIG for Unified Mode System

**Files:**
- Modify: `secator/tasks/ai.py` (after ACTION_HANDLERS)

**Step 1: Add MODE_CONFIG dictionary**

Add after `ACTION_HANDLERS`:

```python
# =============================================================================
# MODE CONFIGURATION
# =============================================================================

MODE_CONFIG = {
    "summarize": {
        "iterative": False,
        "system_prompt_key": "summarize",
        "response_type": "summary",
    },
    "suggest": {
        "iterative": False,
        "system_prompt_key": "suggest",
        "response_type": "suggestion",
    },
    "attack": {
        "iterative": True,
        "system_prompt_key": "attack",
        "allowed_actions": ["execute", "validate", "complete", "stop", "report"],
    },
}
```

**Step 2: Verify the file still parses**

Run: `python -c "import secator.tasks.ai; print('OK')"`
Expected: OK

**Step 3: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "$(cat <<'EOF'
refactor(ai): add MODE_CONFIG for unified mode system

Configuration dictionary defining behavior for summarize, suggest, and attack modes.
Enables future mode extensions without code duplication.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Extract _dispatch_action Method

**Files:**
- Modify: `secator/tasks/ai.py` (inside AI class, after `_parse_attack_actions`)

**Step 1: Add _dispatch_action method to AI class**

Add after `_parse_attack_actions` method (around line 3138):

```python
    def _dispatch_action(self, action: Dict, ctx: 'ActionContext') -> Generator:
        """Dispatch action to appropriate handler.

        Args:
            action: Action dictionary with 'action' key
            ctx: ActionContext with shared execution state

        Yields:
            Results from the handler
        """
        action_type = action.get("action", "")
        handler_name = ACTION_HANDLERS.get(action_type)

        if not handler_name:
            yield Warning(message=f"Unknown action type: {action_type}")
            return

        handler = getattr(self, handler_name, None)
        if not handler:
            yield Warning(message=f"Handler not implemented: {handler_name}")
            return

        yield from handler(action, ctx)
```

**Step 2: Verify the file still parses**

Run: `python -c "import secator.tasks.ai; print('OK')"`
Expected: OK

**Step 3: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "$(cat <<'EOF'
refactor(ai): add _dispatch_action method

Central dispatcher that routes actions to handlers via ACTION_HANDLERS registry.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Extract _handle_validate Method

**Files:**
- Modify: `secator/tasks/ai.py` (inside AI class)

**Step 1: Add _handle_validate method**

Add after `_dispatch_action`:

```python
    def _handle_validate(self, action: Dict, ctx: 'ActionContext') -> Generator:
        """Handle validate action - record validated vulnerability.

        Args:
            action: Validate action with vulnerability details
            ctx: ActionContext (unused but required for interface)

        Yields:
            Vulnerability output type
        """
        vuln_name = action.get("vulnerability", "Unknown")
        target = action.get("target", "")
        proof = action.get("proof", "")
        severity = action.get("severity", "medium")
        steps = action.get("reproduction_steps", [])

        ctx.attack_context["validated_vulns"].append({
            "name": vuln_name,
            "severity": severity,
            "target": target,
        })

        yield Vulnerability(
            name=vuln_name,
            matched_at=target,
            severity=severity,
            confidence="high",
            description=f"AI-validated vulnerability: {vuln_name}",
            provider="ai",
            extra_data={
                "proof_of_concept": proof,
                "reproduction_steps": steps,
                "ai_validated": True,
                "model": ctx.model,
            },
        )
```

**Step 2: Verify the file still parses**

Run: `python -c "import secator.tasks.ai; print('OK')"`
Expected: OK

**Step 3: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "$(cat <<'EOF'
refactor(ai): extract _handle_validate method

Extracted from _mode_attack inline handling. Uses ActionContext for state.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Extract _handle_report Method

**Files:**
- Modify: `secator/tasks/ai.py` (inside AI class)

**Step 1: Add _handle_report method**

Add after `_handle_validate`:

```python
    def _handle_report(self, action: Dict, ctx: 'ActionContext') -> Generator:
        """Handle report action - yield AI report output.

        Args:
            action: Report action with content
            ctx: ActionContext with attack_context

        Yields:
            AI output type with report content
        """
        yield AI(
            content=action.get("content", ""),
            ai_type='report',
            mode='attack',
            extra_data=ctx.attack_context,
        )
```

**Step 2: Verify the file still parses**

Run: `python -c "import secator.tasks.ai; print('OK')"`
Expected: OK

**Step 3: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "$(cat <<'EOF'
refactor(ai): extract _handle_report method

Simple handler for report actions.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Extract _handle_complete Method

**Files:**
- Modify: `secator/tasks/ai.py` (inside AI class)

**Step 1: Add _handle_complete method**

Add after `_handle_report`:

```python
    def _handle_complete(self, action: Dict, ctx: 'ActionContext') -> Generator:
        """Handle complete action - generate summary and prompt for continuation.

        Args:
            action: Complete action (summary field optional)
            ctx: ActionContext with full state

        Yields:
            Info, AI outputs for summary

        Returns via context_update:
            'continue_prompt' if user wants to continue
            'should_break' if user wants to stop
        """
        yield Info(message="Attack loop completed")
        yield Info(message="Generating comprehensive attack summary...")

        full_summary = generate_attack_summary_with_llm(
            ctx.attack_context,
            model=ctx.model,
            api_base=ctx.api_base,
            temperature=ctx.temperature,
        )
        yield AI(
            content=full_summary,
            ai_type='attack_summary',
            mode='attack',
            model=ctx.model,
        )

        # Prompt user for continuation (stored in attack_context for caller to handle)
        user_query = prompt_user_for_continuation()
        if user_query is None:
            yield Info(message="User chose to stop. Ending attack loop.")
            ctx.attack_context["_should_break"] = True
        else:
            ctx.attack_context["_continue_query"] = user_query
            yield Info(message=f"Continuing attack with new query: {user_query}")
```

**Step 2: Verify the file still parses**

Run: `python -c "import secator.tasks.ai; print('OK')"`
Expected: OK

**Step 3: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "$(cat <<'EOF'
refactor(ai): extract _handle_complete method

Handles attack completion with summary generation and continuation prompt.
Uses _should_break and _continue_query in attack_context for control flow.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Extract _handle_stop Method

**Files:**
- Modify: `secator/tasks/ai.py` (inside AI class)

**Step 1: Add _handle_stop method**

Add after `_handle_complete`:

```python
    def _handle_stop(self, action: Dict, ctx: 'ActionContext') -> Generator:
        """Handle stop action - display reason and prompt for continuation.

        Args:
            action: Stop action with reason
            ctx: ActionContext with full state

        Yields:
            AI output with stop reason
        """
        reason = action.get("reason", "No reason provided")
        yield AI(
            content=reason,
            ai_type='stopped',
            mode='attack',
            extra_data={
                "iterations": ctx.attack_context.get("iteration", 0),
                "successful_attacks": len(ctx.attack_context.get("successful_attacks", [])),
                "validated_vulns": len(ctx.attack_context.get("validated_vulns", [])),
            },
        )

        user_query = prompt_user_for_continuation()
        if user_query is None:
            yield Info(message="User chose to stop. Ending attack loop.")
            ctx.attack_context["_should_break"] = True
        else:
            ctx.attack_context["_continue_query"] = user_query
            ctx.attack_context["_stop_reason"] = reason
            yield Info(message=f"Continuing attack with new query: {user_query}")
```

**Step 2: Verify the file still parses**

Run: `python -c "import secator.tasks.ai; print('OK')"`
Expected: OK

**Step 3: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "$(cat <<'EOF'
refactor(ai): extract _handle_stop method

Handles stop action with reason display and continuation prompt.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: Extract _execute_runner Helper

**Files:**
- Modify: `secator/tasks/ai.py` (inside AI class)

**Step 1: Add _execute_runner method**

Add after `_handle_stop`:

```python
    def _execute_runner(
        self,
        action: Dict,
        ctx: 'ActionContext',
        action_num: int,
        total_actions: int
    ) -> Dict:
        """Execute a secator runner (task/workflow/scan) and return batch result.

        Args:
            action: Execute action with type, name, targets, opts
            ctx: ActionContext with execution state
            action_num: Current action number in batch
            total_actions: Total actions in batch

        Returns:
            Dict with action, status, output, result_count, errors for batch results
        """
        exec_type = action.get("type", "task")
        name = action.get("name", "")
        action_targets = action.get("targets", []) or ctx.targets
        opts = action.get("opts", {})

        # Validate options
        valid_opts, invalid_opts, valid_opt_names = self._validate_runner_opts(
            exec_type, name, opts
        )

        if invalid_opts:
            return {
                "action": f"{exec_type} '{name}'",
                "status": "error",
                "output": f"Invalid options: {invalid_opts}. Valid options: {valid_opt_names}",
                "warning": f"[{action_num}/{total_actions}] Invalid options for {exec_type} '{name}': {invalid_opts}"
            }

        # Build CLI command for display and safety check
        cli_opts = " ".join(
            f"--{k.replace('_', '-')} {v}" if v is not True else f"--{k.replace('_', '-')}"
            for k, v in valid_opts.items()
        )
        cli_cmd = f"secator {exec_type[0]} {name} {','.join(action_targets)}"
        if cli_opts:
            cli_cmd += f" {cli_opts}"

        # Safety check
        action_for_safety = {
            "command": cli_cmd,
            "destructive": action.get("destructive", False),
            "aggressive": action.get("aggressive", False),
            "reasoning": action.get("reasoning", ""),
        }
        should_run, modified_cmd = check_action_safety(
            action_for_safety, auto_yes=ctx.auto_yes, in_ci=ctx.in_ci
        )

        if not should_run:
            return {
                "action": cli_cmd,
                "status": "skipped",
                "output": "User declined to run this command.",
                "info": f"[{action_num}/{total_actions}] Skipped: {cli_cmd}"
            }

        if modified_cmd != cli_cmd:
            cli_cmd = modified_cmd

        # Prepare result structure
        result = {
            "action": f"{exec_type.capitalize()} '{name}' on {action_targets}",
            "cli_cmd": cli_cmd,
            "reasoning": action.get("reasoning", ""),
            "exec_type": exec_type,
            "name": name,
            "targets": action_targets,
            "opts": valid_opts,
            "batch_action": f"{action_num}/{total_actions}",
        }

        if ctx.dry_run:
            result["status"] = "dry_run"
            result["output"] = f"[DRY RUN] {exec_type.capitalize()} '{name}' not executed"
            result["result_count"] = 0
            result["errors"] = []
            result["results"] = []
            result["vulnerabilities"] = []
        else:
            runner_results = []
            vulnerabilities = []
            errors = []

            for r in self._execute_secator_runner(exec_type, name, action_targets, valid_opts):
                runner_results.append(r)
                if isinstance(r, Vulnerability):
                    vulnerabilities.append(r)
                elif isinstance(r, Error):
                    errors.append(r.message)

            result_output = format_results_for_llm(runner_results)
            if errors:
                error_text = "\n".join(f"ERROR: {e}" for e in errors)
                result_output = f"{error_text}\n\n{result_output}" if result_output else error_text

            result["status"] = "error" if errors else "success"
            result["output"] = result_output[:2000]
            result["result_count"] = len(runner_results)
            result["errors"] = errors
            result["results"] = runner_results
            result["vulnerabilities"] = vulnerabilities

        return result
```

**Step 2: Verify the file still parses**

Run: `python -c "import secator.tasks.ai; print('OK')"`
Expected: OK

**Step 3: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "$(cat <<'EOF'
refactor(ai): extract _execute_runner helper

Consolidated runner execution logic with validation, safety checks, and result formatting.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: Extract _execute_shell Helper

**Files:**
- Modify: `secator/tasks/ai.py` (inside AI class)

**Step 1: Add _execute_shell method**

Add after `_execute_runner`:

```python
    def _execute_shell(
        self,
        action: Dict,
        ctx: 'ActionContext',
        action_num: int,
        total_actions: int
    ) -> Dict:
        """Execute a shell command and return batch result.

        Args:
            action: Execute action with command and target
            ctx: ActionContext with execution state
            action_num: Current action number in batch
            total_actions: Total actions in batch

        Returns:
            Dict with action, status, output for batch results
        """
        command = action.get("command", "")
        target = action.get("target", "")
        reasoning = action.get("reasoning", "")

        # Safety check
        action_for_safety = {
            "command": command,
            "destructive": action.get("destructive", False),
            "aggressive": action.get("aggressive", False),
            "reasoning": reasoning,
        }
        should_run, modified_cmd = check_action_safety(
            action_for_safety, auto_yes=ctx.auto_yes, in_ci=ctx.in_ci
        )

        if not should_run:
            return {
                "action": command,
                "status": "skipped",
                "output": "User declined to run this command.",
                "info": f"[{action_num}/{total_actions}] Skipped: {command}"
            }

        if modified_cmd != command:
            command = modified_cmd

        result = {
            "action": f"Shell: {command}",
            "command": command,
            "target": target,
            "reasoning": reasoning,
            "batch_action": f"{action_num}/{total_actions}",
        }

        if ctx.dry_run:
            result["status"] = "dry_run"
            result["output"] = "[DRY RUN] Command not executed"
        else:
            output = self._execute_command(command)
            result["status"] = "success"
            result["output"] = output[:2000]

        return result
```

**Step 2: Verify the file still parses**

Run: `python -c "import secator.tasks.ai; print('OK')"`
Expected: OK

**Step 3: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "$(cat <<'EOF'
refactor(ai): extract _execute_shell helper

Consolidated shell execution logic with safety checks and result formatting.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 11: Add _handle_execute Method

**Files:**
- Modify: `secator/tasks/ai.py` (inside AI class)

**Step 1: Add _handle_execute method**

Add after `_execute_shell`:

```python
    def _handle_execute(self, action: Dict, ctx: 'ActionContext') -> Generator:
        """Handle execute action - delegate to runner or shell execution.

        Args:
            action: Execute action with type (task/workflow/scan/shell)
            ctx: ActionContext with execution state

        Yields:
            Info, Warning, AI, Vulnerability outputs

        Note:
            Stores batch_result in action['_result'] for caller to collect
        """
        exec_type = action.get("type", "shell")
        action_num = action.get("_action_num", 1)
        total_actions = action.get("_total_actions", 1)

        if exec_type in ("task", "workflow", "scan"):
            if ctx.disable_secator:
                yield Warning(
                    message=f"[{action_num}/{total_actions}] Secator runners disabled. Rejecting {exec_type} '{action.get('name', '')}'."
                )
                action["_result"] = {
                    "action": f"{exec_type} '{action.get('name', '')}'",
                    "status": "rejected",
                    "output": "Secator runners are disabled. Use shell commands instead."
                }
                return

            result = self._execute_runner(action, ctx, action_num, total_actions)

            # Handle warnings/info from result
            if result.get("warning"):
                yield Warning(message=result["warning"])
            if result.get("info"):
                yield Info(message=result["info"])

            # Display command if not skipped/error
            if result["status"] not in ("skipped", "error"):
                yield AI(
                    content=result.get("cli_cmd", ""),
                    ai_type=exec_type,
                    mode='attack',
                    extra_data={
                        "reasoning": result.get("reasoning", ""),
                        "targets": result.get("targets", []),
                        "opts": result.get("opts", {}),
                        "batch_action": result.get("batch_action", ""),
                    },
                )

                # Yield vulnerabilities
                for vuln in result.get("vulnerabilities", []):
                    self.add_result(vuln, print=True)
                    yield vuln

                if result.get("vulnerabilities"):
                    yield Info(
                        message=f"Found {len(result['vulnerabilities'])} potential vulnerabilities - check for false positives"
                    )

                # Add non-vuln results
                for r in result.get("results", []):
                    if not isinstance(r, Vulnerability):
                        self.add_result(r, print=False)

                if ctx.verbose:
                    yield Info(message=f"[OUTPUT] {_truncate(result.get('output', ''))}")

            # Update attack context
            if result["status"] not in ("skipped", "rejected"):
                ctx.attack_context["successful_attacks"].append({
                    "type": exec_type,
                    "name": action.get("name", ""),
                    "targets": result.get("targets", []),
                    "result_count": result.get("result_count", 0),
                    "output": result.get("output", "")[:2000],
                    "errors": result.get("errors", []),
                })

            action["_result"] = result

        elif exec_type == "shell":
            result = self._execute_shell(action, ctx, action_num, total_actions)

            if result.get("info"):
                yield Info(message=result["info"])

            if result["status"] not in ("skipped",):
                # Display like secator tasks
                console.print("")
                if result.get("reasoning"):
                    console.print(f"🔧 [bold gold3]{result['reasoning']} ...[/]")
                console.print(f"⚡ [bold green]{result['command']}[/]")

                # Save AI records
                shell_ai = AI(
                    content=result["command"],
                    ai_type='shell',
                    mode='attack',
                    extra_data={
                        "reasoning": result.get("reasoning", ""),
                        "target": result.get("target", ""),
                        "batch_action": result.get("batch_action", ""),
                    },
                )
                self.add_result(shell_ai, print=False)

                # Show output
                truncated = result["output"][:1000] + ("..." if len(result["output"]) > 1000 else "")
                console.print(truncated)

                output_ai = AI(
                    content=truncated,
                    ai_type='shell_output',
                    mode='attack',
                )
                self.add_result(output_ai, print=False)

                # Update attack context
                ctx.attack_context["successful_attacks"].append({
                    "type": "shell",
                    "command": result["command"],
                    "target": result.get("target", ""),
                    "output": result["output"][:2000],
                })

            action["_result"] = result

        else:
            yield Warning(message=f"[{action_num}/{total_actions}] Unknown execute type: {exec_type}")
            action["_result"] = {
                "action": f"Unknown type: {exec_type}",
                "status": "error",
                "output": f"Unknown execute type: {exec_type}"
            }
```

**Step 2: Verify the file still parses**

Run: `python -c "import secator.tasks.ai; print('OK')"`
Expected: OK

**Step 3: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "$(cat <<'EOF'
refactor(ai): add _handle_execute method

Main execute handler that delegates to _execute_runner or _execute_shell.
Handles display, result collection, and attack_context updates.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 12: Add _build_action_context Helper

**Files:**
- Modify: `secator/tasks/ai.py` (inside AI class)

**Step 1: Add _build_action_context method**

Add in AI class:

```python
    def _build_action_context(
        self,
        targets: list,
        model: str,
        encryptor: 'SensitiveDataEncryptor',
        api_base: str = None,
        attack_context: dict = None,
        custom_prompt_suffix: str = "",
    ) -> 'ActionContext':
        """Build ActionContext from run_opts and parameters.

        Args:
            targets: List of targets
            model: LLM model name
            encryptor: SensitiveDataEncryptor instance
            api_base: Optional API base URL
            attack_context: Optional existing attack context dict
            custom_prompt_suffix: Custom prompt to append to all prompts

        Returns:
            Populated ActionContext instance
        """
        return ActionContext(
            targets=targets,
            model=model,
            api_base=api_base,
            temperature=float(self.run_opts.get("temperature", 0.7)),
            encryptor=encryptor,
            sensitive=self.run_opts.get("sensitive", True),
            dry_run=self.run_opts.get("dry_run", False),
            verbose=self.run_opts.get("verbose", False),
            dangerous=self.run_opts.get("dangerous", False),
            disable_secator=self.run_opts.get("disable_secator", False),
            max_iterations=int(self.run_opts.get("max_iterations", 10)),
            attack_context=attack_context or {},
            custom_prompt_suffix=custom_prompt_suffix,
            auto_yes=self.run_opts.get("yes", False),
            in_ci=_is_ci(),
        )
```

**Step 2: Verify the file still parses**

Run: `python -c "import secator.tasks.ai; print('OK')"`
Expected: OK

**Step 3: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "$(cat <<'EOF'
refactor(ai): add _build_action_context helper

Factory method to create ActionContext from run_opts.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 13: Add _format_batch_results Helper

**Files:**
- Modify: `secator/tasks/ai.py` (inside AI class)

**Step 1: Add _format_batch_results method**

Add in AI class:

```python
    def _format_batch_results(self, batch_results: list) -> str:
        """Format batch results for LLM prompt.

        Args:
            batch_results: List of result dicts from action handlers

        Returns:
            Formatted markdown string for LLM
        """
        text = ""
        for idx, result in enumerate(batch_results, 1):
            text += f"\n### Action {idx}: {result.get('action', 'Unknown')}\n"
            text += f"**Status:** {result.get('status', 'unknown')}\n"
            if result.get('errors'):
                text += "**Errors (fix these in next attempt):**\n"
                for err in result['errors']:
                    text += f"  - {err}\n"
            if result.get('result_count'):
                text += f"**Results:** {result['result_count']} items\n"
            output = result.get('output', 'No output')[:1500]
            text += f"**Output:**\n```\n{output}\n```\n"
        return text
```

**Step 2: Verify the file still parses**

Run: `python -c "import secator.tasks.ai; print('OK')"`
Expected: OK

**Step 3: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "$(cat <<'EOF'
refactor(ai): add _format_batch_results helper

Formats batch execution results for LLM prompt.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 14: Refactor _mode_attack to Use New Handlers

**Files:**
- Modify: `secator/tasks/ai.py` (`_mode_attack` method)

**Step 1: Replace action processing loop with dispatch calls**

This is the main refactoring step. Replace the action handling section (approximately lines 2688-2976) with dispatcher calls.

Find and replace the section starting with:
```python
                for action_idx, action in enumerate(executable_actions):
```

And ending before:
```python
                # Build batch results prompt for next iteration
```

With:

```python
                for action_idx, action in enumerate(executable_actions):
                    if skip_remaining:
                        break

                    action_type = action.get("action", "")
                    action_num = action_idx + 1

                    # Inject action numbering for handlers
                    action["_action_num"] = action_num
                    action["_total_actions"] = len(executable_actions)

                    # Dispatch to handler
                    for result in self._dispatch_action(action, ctx):
                        yield result

                    # Collect batch result from handler
                    if "_result" in action:
                        batch_results.append(action["_result"])
```

Also need to:
1. Build `ctx` before the loop using `_build_action_context`
2. Use `ctx.attack_context` instead of `attack_context`

**Step 2: Add ctx initialization before the iteration loop**

Before `for iteration in range(max_iterations):`, add:

```python
        # Build action context
        ctx = self._build_action_context(
            targets=targets,
            model=model,
            encryptor=encryptor,
            api_base=api_base,
            attack_context=attack_context,
            custom_prompt_suffix=custom_prompt_suffix,
        )
```

**Step 3: Update attack_context references to ctx.attack_context**

Throughout the method, replace `attack_context` with `ctx.attack_context`.

**Step 4: Verify the file still parses and tests pass**

Run: `python -c "import secator.tasks.ai; print('OK')"`
Run: `secator test unit --task ai --test test_tasks`
Expected: OK, tests pass

**Step 5: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "$(cat <<'EOF'
refactor(ai): refactor _mode_attack to use handlers

Replace inline action processing with _dispatch_action calls.
Uses ActionContext for shared state.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 15: Update Terminal Action Handling

**Files:**
- Modify: `secator/tasks/ai.py` (`_mode_attack` method)

**Step 1: Replace terminal action handling with dispatcher calls**

Replace the section handling complete/stop actions (around lines 2607-2679) with:

```python
                # If we have a terminal action with no executable actions, handle it
                if terminal_action and not executable_actions:
                    # Dispatch terminal action
                    for result in self._dispatch_action(terminal_action, ctx):
                        yield result

                    # Check if we should break or continue
                    if ctx.attack_context.get("_should_break"):
                        break

                    if ctx.attack_context.get("_continue_query"):
                        user_query = ctx.attack_context.pop("_continue_query")
                        stop_reason = ctx.attack_context.pop("_stop_reason", None)

                        executed_cmds = format_executed_commands(ctx.attack_context)
                        if sensitive and executed_cmds:
                            executed_cmds = encryptor.encrypt(executed_cmds)

                        reason_text = f"stopped ({stop_reason})" if stop_reason else "completed its initial objectives"
                        prompt = PROMPT_ATTACK_CONTINUE.format(
                            reason=reason_text,
                            executed_commands=executed_cmds,
                            iterations=iteration + 1,
                            successful_count=len(ctx.attack_context["successful_attacks"]),
                            vuln_count=len(ctx.attack_context["validated_vulns"]),
                            user_query=user_query,
                            targets=targets_str,
                            user_instructions=custom_prompt_suffix
                        )
                        continue
```

**Step 2: Verify tests pass**

Run: `secator test unit --task ai --test test_tasks`
Expected: Tests pass

**Step 3: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "$(cat <<'EOF'
refactor(ai): update terminal action handling to use dispatch

Complete and stop actions now use _dispatch_action with context flags.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 16: Use _format_batch_results in _mode_attack

**Files:**
- Modify: `secator/tasks/ai.py` (`_mode_attack` method)

**Step 1: Replace inline batch formatting with helper call**

Find the section (around lines 2978-2991):
```python
                    batch_results_text = ""
                    for idx, result in enumerate(batch_results, 1):
                        ...
```

Replace with:
```python
                    batch_results_text = self._format_batch_results(batch_results)
```

**Step 2: Verify tests pass**

Run: `secator test unit --task ai --test test_tasks`
Expected: Tests pass

**Step 3: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "$(cat <<'EOF'
refactor(ai): use _format_batch_results in _mode_attack

Replace inline formatting with extracted helper method.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 17: Move Prompts to End of File

**Files:**
- Modify: `secator/tasks/ai.py`

**Step 1: Cut prompt templates section**

Cut the section from `PROMPT_SUMMARIZE = """` through `get_system_prompt()` function (lines ~345-893).

**Step 2: Paste after AI class**

Paste at the very end of the file, after the AI class definition.

**Step 3: Add section header**

Add at the beginning of the moved section:
```python
# =============================================================================
# PROMPT TEMPLATES (moved to end for better code navigation)
# =============================================================================
```

**Step 4: Verify file still parses**

Run: `python -c "import secator.tasks.ai; print('OK')"`
Expected: OK

**Step 5: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "$(cat <<'EOF'
refactor(ai): move prompts to end of file

Better code navigation - AI class is now near top of file.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 18: Consolidate Similar Prompts

**Files:**
- Modify: `secator/tasks/ai.py` (prompts section)

**Step 1: Merge PROMPT_ANALYZE_TARGETS and PROMPT_ANALYZE_RESULTS**

Replace both with single `PROMPT_ANALYZE`:

```python
PROMPT_ANALYZE = """Analyze the following for a penetration test:

## Targets
{targets}

{context_section}

{custom_prompt}"""
```

Update `_mode_summarize` to use:
```python
context_section = f"## Findings\n{context_text}" if results else ""
prompt = PROMPT_ANALYZE.format(
    targets=", ".join(targets),
    context_section=context_section,
    custom_prompt=custom_section
)
```

**Step 2: Merge PROMPT_SUGGEST_TARGETS and PROMPT_SUGGEST_RESULTS**

Replace both with single `PROMPT_SUGGEST_NEXT`:

```python
PROMPT_SUGGEST_NEXT = """Based on the current state, suggest specific Secator commands:

## Targets
{targets}

{context_section}

Provide 3-5 specific commands with reasoning.

{custom_prompt}"""
```

**Step 3: Merge PROMPT_ATTACK_START_NO_RESULTS and PROMPT_ATTACK_START_WITH_RESULTS**

Replace both with single `PROMPT_ATTACK_START`:

```python
PROMPT_ATTACK_START = """You are conducting authorized penetration testing.

## Targets
{targets}

{context_section}

## Instructions
{instructions}"""
```

**Step 4: Verify tests pass**

Run: `secator test unit --task ai --test test_tasks`
Expected: Tests pass

**Step 5: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "$(cat <<'EOF'
refactor(ai): consolidate similar prompt templates

Merge analyze, suggest, and attack start prompts with conditional sections.
Reduces prompt count from ~30 to ~15.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 19: Final Cleanup and Line Count Verification

**Files:**
- Modify: `secator/tasks/ai.py`

**Step 1: Remove any dead code**

Search for any unused functions or variables that can be removed.

**Step 2: Verify line count reduction**

Run: `wc -l secator/tasks/ai.py`
Target: ~2000-2500 lines (down from 3343)

**Step 3: Run full test suite**

Run: `secator test unit --task ai --test test_tasks`
Run: `secator test integration --test test_tasks --tasks ai` (if available)
Expected: All tests pass

**Step 4: Commit**

```bash
git add secator/tasks/ai.py
git commit -m "$(cat <<'EOF'
refactor(ai): final cleanup - Phase 1 DRY refactor complete

- Reduced from 3343 to ~2000 lines
- Unified mode system via MODE_CONFIG
- Handler dispatch via ACTION_HANDLERS
- ActionContext/ActionResult data structures
- Consolidated prompts

Ready for Phase 2: new action types (query, output_type, prompt)

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Summary

| Task | Description | Est. Impact |
|------|-------------|-------------|
| 1 | Add ActionResult, ActionContext dataclasses | +30 lines |
| 2 | Add ACTION_HANDLERS registry | +15 lines |
| 3 | Add MODE_CONFIG | +20 lines |
| 4 | Extract _dispatch_action | +20 lines |
| 5 | Extract _handle_validate | +25 lines |
| 6 | Extract _handle_report | +10 lines |
| 7 | Extract _handle_complete | +30 lines |
| 8 | Extract _handle_stop | +25 lines |
| 9 | Extract _execute_runner | +80 lines |
| 10 | Extract _execute_shell | +50 lines |
| 11 | Add _handle_execute | +100 lines |
| 12 | Add _build_action_context | +30 lines |
| 13 | Add _format_batch_results | +20 lines |
| 14-16 | Refactor _mode_attack | -400 lines |
| 17 | Move prompts to end | 0 lines |
| 18 | Consolidate prompts | -150 lines |
| 19 | Final cleanup | -50 lines |

**Net reduction: ~300-400 lines** while adding extensibility infrastructure.
