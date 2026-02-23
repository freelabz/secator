"""AI-powered penetration testing task using LiteLLM."""

import hashlib
import json
import logging
import os
import re
import signal
import subprocess
import time
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, Generator, List, Optional, Tuple

import click

from dataclasses import fields
from secator.config import CONFIG
from secator.decorators import task
from secator.output_types import AI, Error, Info, Tag, Vulnerability, Warning, FINDING_TYPES
from secator.rich import console
from secator.runners import PythonRunner

logger = logging.getLogger(__name__)


# =============================================================================
# PROMPT LOADING UTILITIES
# =============================================================================

def load_prompt_from_file_or_text(prompt_value: str) -> Tuple[str, bool, bool]:
    """Load prompt from file path or return as-is if it's direct text.

    Args:
        prompt_value: Either a file path or direct prompt text.

    Returns:
        Tuple of (content, is_from_file, is_markdown)
    """
    if not prompt_value:
        return "", False, False

    # Check if it's a file path that exists
    expanded_path = os.path.expanduser(prompt_value)
    if os.path.isfile(expanded_path):
        try:
            with open(expanded_path, 'r', encoding='utf-8') as f:
                content = f.read()
            is_markdown = expanded_path.lower().endswith('.md')
            return content, True, is_markdown
        except (IOError, OSError) as e:
            logger.warning(f"Could not read prompt file {expanded_path}: {e}")
            # Fall through to return as text
            pass

    return prompt_value, False, False


def format_prompt_for_display(content: str, is_markdown: bool = False) -> str:
    """Format prompt content for console display.

    Args:
        content: The prompt content.
        is_markdown: Whether the content is markdown.

    Returns:
        Formatted string for display.
    """
    from secator.output_types.tag import is_markdown as detect_markdown, render_markdown_for_rich
    from secator.utils import rich_to_ansi

    # Auto-detect markdown if not explicitly specified
    if not is_markdown:
        is_markdown = detect_markdown(content)

    if is_markdown:
        # Render markdown for rich console output
        rendered = render_markdown_for_rich(content)
        return f"\n{rendered}"
    else:
        return content


# =============================================================================
# DYNAMIC LIBRARY REFERENCE BUILDER
# =============================================================================


def build_library_reference() -> str:
    """Build library reference dynamically from secator's registered tasks, workflows, and scans.

    Returns:
        Formatted string containing available runners and their options.
    """
    from secator.loader import get_configs_by_type

    lines = []
    lines.append("=== SECATOR RUNNERS ===\n")
    lines.append("RUNNER TYPES:")
    lines.append("- task: Single tool execution (use 'secator x TASK TARGET')")
    lines.append("- workflow: Multi-task pipelines (use 'secator w WORKFLOW TARGET')")
    lines.append("- scan: Comprehensive scans (use 'secator s SCAN TARGET')")
    lines.append("")

    # Get workflows dynamically with descriptions
    try:
        workflows = get_configs_by_type('workflow')
        if workflows:
            lines.append("=== AVAILABLE WORKFLOWS ===\n")
            workflow_names = [w.name for w in sorted(workflows, key=lambda x: x.name)]
            lines.append(", ".join(workflow_names))
            lines.append("")
    except Exception:
        pass

    # Get scans dynamically with descriptions
    try:
        scans = get_configs_by_type('scan')
        if scans:
            lines.append("=== AVAILABLE SCANS ===\n")
            scan_names = [s.name for s in sorted(scans, key=lambda x: x.name)]
            lines.append(", ".join(scan_names))
            lines.append("")
    except Exception:
        pass

    # Get profiles dynamically
    try:
        profiles = get_configs_by_type('profile')
        if profiles:
            lines.append("=== AVAILABLE PROFILES ===\n")
            profile_names = [p.name for p in sorted(profiles, key=lambda x: x.name)]
            lines.append(", ".join(profile_names))
            lines.append("")
    except Exception:
        pass

    # Get tasks and their options dynamically
    lines.append("=== AVAILABLE TASKS ===\n")

    try:
        from secator.loader import discover_tasks
        from secator.definitions import OPT_NOT_SUPPORTED

        tasks = discover_tasks()
        # Focus on commonly used security tasks
        priority_tasks = ['httpx', 'nmap', 'nuclei', 'katana', 'ffuf', 'subfinder',
                          'dalfox', 'feroxbuster', 'gospider', 'dirsearch', 'gau',
                          'waybackurls', 'dnsx', 'masscan', 'rustscan', 'testssl']

        for task_cls in sorted(tasks, key=lambda t: (t.__name__ not in priority_tasks, t.__name__)):
            task_name = task_cls.__name__

            # Get task description from docstring
            task_desc = (task_cls.__doc__ or "").strip().split('\n')[0] or "No description"

            # Get task-specific options
            task_opts = list(getattr(task_cls, 'opts', {}).keys())

            # Get generic options that this task supports (from opt_key_map)
            opt_key_map = getattr(task_cls, 'opt_key_map', {})
            supported_generic = [k for k, v in opt_key_map.items() if v != OPT_NOT_SUPPORTED]

            # Combine all options
            all_opts = sorted(set(task_opts + supported_generic))

            lines.append(f"{task_name}: {task_desc}")
            if all_opts:
                opts_str = ", ".join(all_opts)
                lines.append(f"  options: {opts_str}")
            lines.append("")
    except Exception:
        pass

    # Add option format notes
    lines.append("=== OPTION FORMATS ===\n")
    lines.append("header: Use format 'key1:value1;;key2:value2' for multiple headers")
    lines.append("  Example: header='Authorization:Bearer token;;X-Custom:value'")
    lines.append("")
    lines.append("NOTE: Do NOT use options not listed above. They will be rejected.")

    return "\n".join(lines)


def get_library_reference() -> str:
    """Get the library reference, using cached version if available.

    Returns:
        Library reference string.
    """
    # Use a module-level cache to avoid rebuilding on every call
    if not hasattr(get_library_reference, '_cache'):
        get_library_reference._cache = build_library_reference()
    return get_library_reference._cache


def build_wordlists_reference() -> str:
    """Build wordlists reference from CONFIG.wordlists.

    Returns:
        Formatted wordlists reference string.
    """
    from secator.config import CONFIG

    lines = ["USING WORDLISTS:"]
    lines.append("Use predefined wordlists by name with the 'wordlist' option. Available wordlists:")

    # Add templates (predefined wordlists)
    if CONFIG.wordlists.templates:
        for name in CONFIG.wordlists.templates.keys():
            lines.append(f"  - {name}")

    # Add defaults info
    if CONFIG.wordlists.defaults:
        lines.append("\nDefault wordlists by type:")
        for wl_type, wl_name in CONFIG.wordlists.defaults.items():
            lines.append(f"  - {wl_type}: {wl_name}")

    lines.append("\nExample usage:")
    lines.append('{"action": "execute", "type": "task", "name": "feroxbuster", "targets": ["http://example.com"], "opts": {"wordlist": "bo0m_fuzz"}, "reasoning": "...", "expected_outcome": "..."}')

    return "\n".join(lines)


def get_wordlists_reference() -> str:
    """Get the wordlists reference, using cached version if available.

    Returns:
        Wordlists reference string.
    """
    if not hasattr(get_wordlists_reference, '_cache'):
        get_wordlists_reference._cache = build_wordlists_reference()
    return get_wordlists_reference._cache


# =============================================================================
# PROMPT TEMPLATES
# =============================================================================
# All prompts are defined here with named placeholders for easy customization.
# Use .format(**kwargs) to fill in the placeholders.
# =============================================================================


def build_cheatsheet() -> str:
    """Build cheatsheet dynamically from secator's registered tasks, workflows, and scans.

    Returns:
        Formatted cheatsheet string.
    """
    from secator.loader import get_configs_by_type

    lines = []
    lines.append("=== SECATOR CHEATSHEET ===\n")

    # Task examples (static - these are example commands)
    lines.append("TASKS (secator x <tool> <target>):")
    lines.append("  secator x nmap <HOST> -p 1-1000        # port scan")
    lines.append("  secator x httpx <URL>                  # HTTP probe")
    lines.append("  secator x nuclei <URL> -tags cve       # vuln scan")
    lines.append("  secator x ffuf <URL>/FUZZ -w wordlist  # directory fuzzing")
    lines.append("  secator x katana <URL>                 # web crawling")
    lines.append("  secator x subfinder <DOMAIN>           # subdomain enum")
    lines.append("")

    # Common options (static - these are examples)
    lines.append("COMMON OPTIONS:")
    lines.append("  -rl 10                   # rate limit (req/sec)")
    lines.append("  -delay 1                 # delay between requests")
    lines.append("  -proxy http://127.0.0.1:8080")
    lines.append("  -pf <profile>            # use a profile")
    lines.append("  -o json                  # output format")
    lines.append("")

    # Available tasks (dynamic)
    try:
        tasks = get_configs_by_type('task')
        task_names = sorted([t.name for t in tasks])
        if task_names:
            lines.append("AVAILABLE TASKS:")
            lines.append(f"  {', '.join(task_names)}")
            lines.append("")
    except Exception:
        pass

    # Available scans (dynamic)
    try:
        scans = get_configs_by_type('scan')
        scan_names = sorted([s.name for s in scans])
        if scan_names:
            lines.append("AVAILABLE SCANS:")
            for name in scan_names:
                lines.append(f"  secator s {name} <TARGET>")
            lines.append("")
    except Exception:
        pass

    # Available workflows (dynamic)
    try:
        workflows = get_configs_by_type('workflow')
        workflow_names = sorted([w.name for w in workflows])
        if workflow_names:
            lines.append("AVAILABLE WORKFLOWS:")
            for name in workflow_names:
                lines.append(f"  secator w {name} <TARGET>")
            lines.append("")
    except Exception:
        pass

    # Available profiles (dynamic)
    try:
        profiles = get_configs_by_type('profile')
        profile_names = sorted([p.name for p in profiles])
        if profile_names:
            lines.append("AVAILABLE PROFILES:")
            lines.append(f"  {', '.join(profile_names)}")
            lines.append("")
    except Exception:
        pass

    # Piping and reference (static)
    lines.append("RULES:")
    lines.append("  - ALWAYS use 'secator x <tool>' instead of raw tool commands")
    lines.append("  - ONLY use options that exist (check task file if unsure)")

    return "\n".join(lines)


def get_cheatsheet() -> str:
    """Get the cheatsheet, using cached version if available.

    Returns:
        Cheatsheet string.
    """
    if not hasattr(get_cheatsheet, '_cache'):
        get_cheatsheet._cache = build_cheatsheet()
    return get_cheatsheet._cache



# SECATOR_LIBRARY_REFERENCE is now dynamically generated by get_library_reference()

# -----------------------------------------------------------------------------
# System Prompts (used as system message for LLM)
# -----------------------------------------------------------------------------

PROMPT_SUMMARIZE = """You are a senior penetration tester analyzing security scan results.
Your task is to:
1. Summarize the key findings from the scan results
2. Identify potential attack paths based on discovered vulnerabilities, services, and endpoints
3. Prioritize findings by severity and exploitability
4. Highlight any interesting patterns or relationships between findings

## Response Format

Your response MUST be formatted in Markdown with the following sections:

### Executive Summary
Brief overview of findings (2-3 sentences).

### Vulnerabilities

For each vulnerability found, use this format:

#### [Vulnerability Name]
| Field | Value |
|-------|-------|
| **Severity** | critical/high/medium/low/info |
| **Confidence** | high/medium/low |
| **Target(s)** | URL or host where found |
| **CVSS Score** | X.X (if available) |
| **Provider** | Tool that found it |
| **ID** | CVE/vulnerability ID (if available) |

**Description:** Brief description of the vulnerability and its impact.

**References:**
- Link 1
- Link 2

---

### Attack Paths
Potential exploitation chains based on the findings.

### Recommendations
Prioritized next steps for deeper testing.

## Guidelines
- Use proper Markdown formatting (headers, tables, bold, lists)
- Include ALL vulnerabilities found, grouped by severity
- Be thorough but concise
- Focus on actionable intelligence
- Include actual targets/URLs from the findings, not placeholders
- CRITICAL: ONLY report vulnerabilities that are explicitly present in the provided findings
- DO NOT invent, assume, or speculate about vulnerabilities without evidence from the scan data
- If there are no vulnerabilities in the findings, say so - do not fabricate findings"""

PROMPT_SUGGEST = """You are a senior penetration tester recommending next steps for a security assessment.
Based on the scan results and targets, suggest specific Secator tasks to run next.

{cheatsheet}

Provide 3-5 specific secator commands with brief reasoning for each.
Include the actual target from the findings, not placeholders."""

PROMPT_ATTACK = """You are an autonomous penetration testing agent conducting authorized security testing.

MISSION:
1. Analyze findings and identify exploitable vulnerabilities
2. Execute attacks using secator runners or shell commands
3. Validate exploits with proof-of-concept
4. Document findings

{library_reference}

RULES:
- NEVER repeat commands already executed (check "ALREADY EXECUTED" section)
- Each iteration must try a DIFFERENT tool, target, or approach
- By DEFAULT, prefer single TASKS over workflows/scans (less intrusive, more targeted)
- Only use workflows/scans when user explicitly requests "comprehensive", "full", or "deep" recon
- Prefer secator runners over raw shell commands
- Only use options that exist for the runner
- If you've exhausted all useful actions, use "complete" or "stop"

WORKSPACE QUERIES:
- When querying workspace data, be SPECIFIC to avoid context window overflow
- Use fine-grained queries: filter by type (vulnerability, url, port), severity, or target
- Example: query only critical/high vulnerabilities, or only URLs for a specific host
- Avoid querying "all results" - instead query what's relevant for your current analysis

HANDLING VULNERABILITIES:
When vulnerabilities are found by Secator tools:
1. CHECK FOR FALSE POSITIVES: If a vulnerability was reported on a very wide version range (e.g., "nginx < 99.0"), it's likely a false positive - skip it
2. IF MARKED EXPLOITABLE (has 'exploitable' tag or associated exploits in results):
   - Download and read exploit code (use curl to fetch from exploit-db, GitHub, etc.)
   - Figure out a simple reproduction command (e.g., a curl command)
   - Run the exploit - mark this as a DESTRUCTIVE action: {{"destructive": true}}
   - Use "validate" action only after successful exploitation with actual proof
3. IF NOT EXPLOITABLE: Don't waste time - continue with other analysis

RESPONSE FORMAT:
- FIRST: Provide a brief analysis of the current situation (1-3 sentences)
- THEN: Respond with a JSON array of actions: [{{"action": ...}}, {{"action": ...}}]
- You can include MULTIPLE execute actions to run in sequence
- Put your reasoning in the "reasoning" field inside each action
- Keep reasoning brief (1-2 sentences)
- All actions will be executed sequentially and results reported back to you

ACTIONS:

Execute secator runner:
{{"action": "execute", "type": "task|workflow|scan", "name": "runner_name", "targets": ["target"], "opts": {{}}, "reasoning": "brief reason", "expected_outcome": "expected result"}}

Execute shell command:
{{"action": "execute", "type": "shell", "command": "curl -s http://example.com", "target": "example.com", "reasoning": "brief reason", "expected_outcome": "expected result"}}

Validate vulnerability (ONLY use when you have confirmed a vulnerability with actual proof and reproduction steps):
{{"action": "validate", "vulnerability": "name", "target": "url", "proof": "actual evidence from output", "severity": "critical|high|medium|low|info", "reproduction_steps": ["step1", "step2"]}}

Complete (when done testing):
{{"action": "complete", "summary": "findings summary"}}

Stop (when user instruction says to stop, or no actions possible):
{{"action": "stop", "reason": "why stopping"}}

EXAMPLE MULTI-ACTION RESPONSE:
[
  {{"action": "execute", "type": "task", "name": "httpx", "targets": ["example.com"], "opts": {{}}, "reasoning": "Probe for live hosts", "expected_outcome": "List of live URLs"}},
  {{"action": "execute", "type": "task", "name": "nuclei", "targets": ["http://example.com"], "opts": {{"templates": "cves"}}, "reasoning": "Scan for known CVEs", "expected_outcome": "CVE findings"}}
]

USING PROFILES:
To apply profiles (e.g., aggressive, stealth, passive), use the "profiles" key in opts:
{{"action": "execute", "type": "task", "name": "nuclei", "targets": ["http://example.com"], "opts": {{"profiles": ["aggressive"]}}, "reasoning": "...", "expected_outcome": "..."}}

{wordlists_reference}"""

PROMPT_ATTACK_SHELL_ONLY = """You are an autonomous penetration testing agent conducting authorized security testing.

MISSION:
1. Analyze findings and identify exploitable vulnerabilities
2. Execute attacks using shell commands (curl, nmap, httpx, wget, etc.)
3. Validate exploits with proof-of-concept
4. Document findings

RULES:
- NEVER repeat commands already executed (check "ALREADY EXECUTED" section)
- Each iteration must try a DIFFERENT tool, target, or approach
- Use standard security tools via shell commands
- If you've exhausted all useful actions, use "complete" or "stop"

WORKSPACE QUERIES:
- When querying workspace data, be SPECIFIC to avoid context window overflow
- Use fine-grained queries: filter by type (vulnerability, url, port), severity, or target
- Avoid querying "all results" - instead query what's relevant for your current analysis

HANDLING VULNERABILITIES:
When vulnerabilities are found:
1. CHECK FOR FALSE POSITIVES: If reported on a very wide version range, it's likely false positive - skip it
2. IF MARKED EXPLOITABLE (has 'exploitable' tag or associated exploits):
   - Download and read exploit code (curl from exploit-db, GitHub, etc.)
   - Figure out a simple reproduction command (e.g., a curl command)
   - Run the exploit - mark as DESTRUCTIVE: {{"destructive": true}}
   - Use "validate" action only after successful exploitation with actual proof
3. IF NOT EXPLOITABLE: Continue with other analysis

RESPONSE FORMAT:
- FIRST: Provide a brief analysis of the current situation (1-3 sentences)
- THEN: Respond with a JSON array of actions: [{{"action": ...}}, {{"action": ...}}]
- You can include MULTIPLE execute actions to run in sequence
- Put your reasoning in the "reasoning" field inside each action
- Keep reasoning brief (1-2 sentences)
- All actions will be executed sequentially and results reported back to you

ACTIONS:

Execute shell command:
{{"action": "execute", "type": "shell", "command": "curl -s http://example.com", "target": "example.com", "reasoning": "brief reason", "expected_outcome": "expected result"}}

Validate vulnerability (ONLY use when you have confirmed a vulnerability with actual proof and reproduction steps):
{{"action": "validate", "vulnerability": "name", "target": "url", "proof": "actual evidence from output", "severity": "critical|high|medium|low|info", "reproduction_steps": ["step1", "step2"]}}

Complete (when done testing):
{{"action": "complete", "summary": "findings summary"}}

Stop (when user instruction says to stop, or no actions possible):
{{"action": "stop", "reason": "why stopping"}}

EXAMPLE MULTI-ACTION RESPONSE:
[
  {{"action": "execute", "type": "shell", "command": "nmap -sV -p- example.com", "target": "example.com", "reasoning": "Full port scan", "expected_outcome": "Open ports and services"}},
  {{"action": "execute", "type": "shell", "command": "curl -I http://example.com", "target": "example.com", "reasoning": "Check HTTP headers", "expected_outcome": "Server headers"}}
]

COMMON SHELL COMMANDS:
- curl: HTTP requests, API testing
- nmap: Port scanning, service detection
- httpx: HTTP probing, tech detection
- wget: File download, web requests
- nikto: Web vulnerability scanning
- sqlmap: SQL injection testing
- gobuster/ffuf: Directory fuzzing
- nuclei: Vulnerability scanning"""

PROMPT_INITIAL_RECON = """You are a senior penetration tester starting a new security assessment.
Given the target(s), suggest an initial reconnaissance plan using Secator tasks.

{cheatsheet}

Suggest 2-3 initial commands to start the assessment.
Format each as: secator x <task> <target> [options]"""

PROMPT_INTENT_ANALYSIS = """You are a penetration testing assistant analyzing user requests.

Given the user's prompt and optional targets, determine:
1. Which mode to use (summarize, suggest, or attack)
2. Whether workspace data is needed (e.g., if user asks about previous results, findings, or wants to analyze workspace data)
3. What workspace queries to run to fetch relevant data (only if use_workspace is true)

## Available Output Types

{output_types_schema}

## Query Operators

- Direct match: {{"field": "value"}}
- Regex: {{"field": {{"$regex": "pattern"}}}}
- Contains: {{"field": {{"$contains": "substring"}}}}
- Comparison: {{"field": {{"$gt|$gte|$lt|$lte": value}}}}
- In list: {{"field": {{"$in": ["a", "b"]}}}}
- Not equal: {{"field": {{"$ne": value}}}}

NOTE: Workspace filtering is automatic. Do NOT include workspace-related fields in queries.

## Response Format (JSON)

{{
    "mode": "summarize|suggest|attack",
    "use_workspace": true|false,
    "queries": [
        {{"_type": "vulnerability", "severity": {{"$in": ["critical", "high"]}}}},
        {{"_type": "url", "url": {{"$contains": "login"}}}}
    ],
    "reasoning": "Brief explanation of why this mode and these queries"
}}

IMPORTANT: Default use_workspace to FALSE. Only set to true if the user EXPLICITLY asks for workspace data.

Set use_workspace to TRUE only when user explicitly:
- Says "workspace", "previous results", "existing findings", "what we found", "our data"
- Asks to "summarize results", "analyze findings", "review what we have"
- References data from previous scans explicitly

Set use_workspace to FALSE (default) when:
- User provides targets (URLs, domains, IPs) to scan
- User asks to run tools, scans, or attacks on targets
- User doesn't explicitly mention workspace/previous data
- User says "scan", "test", "attack", "enumerate", "fuzz", etc.

Example: "Scan http://example.com with nuclei" -> use_workspace: false
Example: "Summarize the vulnerabilities we found" -> use_workspace: true

Respond with ONLY the JSON object, no additional text."""

# -----------------------------------------------------------------------------
# User Prompts (used as user message content)
# -----------------------------------------------------------------------------

PROMPT_ANALYZE_TARGETS = """Analyze these targets and suggest an initial penetration testing approach:

## Targets
{targets}

Provide a brief initial assessment."""

PROMPT_ANALYZE_RESULTS = """Analyze the following penetration test results and provide a summary:

## Targets
{targets}

## Findings
{context}

{custom_prompt}"""

PROMPT_SUGGEST_TARGETS = """You are starting a new penetration test on these targets:

## Targets
{targets}

Suggest 3-5 initial secator commands to start the assessment."""

PROMPT_SUGGEST_RESULTS = """Based on these penetration test results, suggest specific Secator commands to run next:

## Targets
{targets}

## Current Findings
{context}

Provide 3-5 specific commands with reasoning.

{custom_prompt}"""

PROMPT_ATTACK_START_NO_RESULTS = """You are starting authorized penetration testing on these targets:

## Targets
{targets}

## Instructions
Start with reconnaissance to identify attack surface. Respond with a JSON action."""

PROMPT_ATTACK_START_WITH_RESULTS = """You are conducting authorized penetration testing.

## Current Findings
{context}

## Targets
{targets}

## Instructions
Analyze the findings and plan your first attack. Respond with a JSON action."""

PROMPT_ATTACK_ITERATION = """{action_description}

Results:
{output}

{executed_commands}
{user_instructions}

## Instruction
Analyze the results and decide next actions. You can return multiple execute actions as a JSON array."""

PROMPT_ATTACK_SHELL_RESULT = """Shell command executed:
{command}

Output:
{output}

{executed_commands}
{user_instructions}

## Instruction
Analyze the output and decide next actions. You can return multiple execute actions as a JSON array."""

PROMPT_ATTACK_BATCH_RESULTS = """## Batch Execution Results

The following {action_count} actions were executed:

{batch_results}

{executed_commands}
{user_instructions}

## Instruction
FIRST, provide your analysis (this will be shown to the user):
- Summarize what was found in each command's output
- If there were ERRORS, explain what went wrong and how to fix it
- Highlight any interesting findings or vulnerabilities

THEN, provide your next actions as a JSON array.
If a command failed due to invalid options or wordlists, retry with corrected parameters."""

PROMPT_ATTACK_VALIDATION = """Vulnerability validated: {vuln_name}

{executed_commands}
{user_instructions}

## Instruction
Continue testing or mark complete if all attack paths are exhausted."""

PROMPT_ATTACK_ERROR_INVALID_OPTS = """Invalid options for {exec_type} '{name}': {invalid_opts}

Valid options are: {valid_opts}

{executed_commands}
{user_instructions}

## Instruction
Please retry with valid options only. Use the SAME targets: {targets}"""

PROMPT_ATTACK_SKIPPED = """User skipped action: {command}.

{executed_commands}
{user_instructions}

## Instruction
Choose another action. Use ONLY these targets: {targets}"""

PROMPT_ATTACK_REPORT = """Report noted.

{executed_commands}
{user_instructions}

## Instruction
Continue with next action."""

PROMPT_ATTACK_INVALID_JSON = """Your previous response was not valid JSON and could not be parsed.

Your response was:
{response}

{executed_commands}
{user_instructions}

## Instruction
Please respond with a valid JSON action in one of these formats:
- {{"action": "execute", "type": "task|workflow|scan", "name": "...", "targets": [...], "opts": {{}}, "reasoning": "...", "expected_outcome": "..."}}
- {{"action": "execute", "type": "shell", "command": "...", "target": "...", "reasoning": "...", "expected_outcome": "..."}}
- {{"action": "validate", "vulnerability": "...", "target": "...", "proof": "...", "severity": "...", "reproduction_steps": [...]}}
- {{"action": "complete", "summary": "..."}}
- {{"action": "stop", "reason": "..."}}

IMPORTANT: Use ONLY these targets: {targets}"""

PROMPT_ATTACK_ERROR_UNKNOWN_TYPE = """Unknown execute type '{exec_type}'.

{executed_commands}
{user_instructions}

## Instruction
Use: task, workflow, scan, or shell. Use ONLY these targets: {targets}"""

PROMPT_ATTACK_ERROR_UNKNOWN_ACTION = """Unknown action '{action_type}'.

{executed_commands}
{user_instructions}

## Instruction
Use: execute, validate, report, stop, or complete. Use ONLY these targets: {targets}"""

PROMPT_ATTACK_ERROR_EXCEPTION = """Previous action failed with error: {error}.

{executed_commands}
{user_instructions}

## Instruction
Try a different approach. Use ONLY these targets: {targets}"""

PROMPT_VULN_PROOF_OF_CONCEPT = """A vulnerability was discovered by {tool_name}:

Vulnerability: {vuln_name}
Severity: {severity}
Target: {target}
Provider: {provider}
Description: {description}

Based on the scan results below, provide a proof of concept and reproduction steps for this vulnerability.

Scan Output:
{scan_output}

RESPONSE FORMAT:
Respond with ONLY a JSON object:
{{"proof_of_concept": "detailed proof showing the vulnerability exists", "reproduction_steps": ["step1", "step2", ...], "impact": "potential impact description", "remediation": "suggested fix"}}"""

PROMPT_VULN_BATCH_PROOF_OF_CONCEPT = """The following vulnerabilities were discovered during a security scan.
For EACH vulnerability, provide a proof of concept and reproduction steps.

## Vulnerabilities

{vulnerabilities_list}

## Scan Output (for context)

{scan_output}

## Response Format

Respond with ONLY a JSON array, one object per vulnerability in the SAME ORDER as listed above:
[
  {{"id": 0, "proof_of_concept": "...", "reproduction_steps": ["step1", ...], "impact": "...", "remediation": "..."}},
  {{"id": 1, "proof_of_concept": "...", "reproduction_steps": ["step1", ...], "impact": "...", "remediation": "..."}}
]

IMPORTANT: Include the "id" field matching the vulnerability index (0, 1, 2, ...) to ensure correct mapping."""

PROMPT_ATTACK_FINAL_SUMMARY = """You are a senior penetration tester summarizing an automated security assessment.

## Targets
{targets}

## Commands Executed
{executed_commands}

## Raw Findings
{findings}

Based on the above data, provide a comprehensive summary in Markdown format:

### Executive Summary
Brief overview of what was tested and key findings (2-3 sentences).

### Interesting URLs
List URLs that warrant further investigation (login pages, admin panels, API endpoints, file uploads, etc.):
- URL and why it's interesting

### Vulnerabilities Found
List any vulnerabilities or security issues discovered:
- Vulnerability name, severity, target, and brief description

### Technologies Detected
List interesting technologies that could be attack vectors:
- Technology and potential security implications

### Recommended Next Steps
Suggest 3-5 specific commands or approaches to continue the assessment:
- `command` - reasoning

Keep the summary concise but actionable. Focus on findings that could lead to exploitation."""

PROMPT_ATTACK_CONTINUE = """The attack run has {reason}.

{executed_commands}

Summary so far:
- Iterations completed: {iterations}
- Successful attacks: {successful_count}
- Validated vulnerabilities: {vuln_count}
{user_instructions}

## Instruction
The user has provided additional instructions: {user_query}

Continue the attack with this new direction. Use ONLY these targets: {targets}"""


def get_system_prompt(mode: str, disable_secator: bool = False) -> str:
    """Get system prompt for a given mode.

    Args:
        mode: The operation mode (summarize, suggest, attack, initial_recon)
        disable_secator: If True, use shell-only prompts without secator references
    """
    if disable_secator:
        prompts = {
            "summarize": PROMPT_SUMMARIZE,
            "suggest": PROMPT_SUMMARIZE,  # No suggestions without secator
            "attack": PROMPT_ATTACK_SHELL_ONLY,
            "initial_recon": PROMPT_SUMMARIZE,
        }
    else:
        prompts = {
            "summarize": PROMPT_SUMMARIZE,
            "suggest": PROMPT_SUGGEST.format(cheatsheet=get_cheatsheet()),
            "attack": PROMPT_ATTACK.format(
                library_reference=get_library_reference(),
                wordlists_reference=get_wordlists_reference()
            ),
            "initial_recon": PROMPT_INITIAL_RECON.format(cheatsheet=get_cheatsheet()),
        }
    return prompts.get(mode, PROMPT_SUMMARIZE)


# =============================================================================
# END PROMPT TEMPLATES
# =============================================================================


def format_executed_commands(attack_context: dict) -> str:
    """Format executed commands for clear display in prompts.

    Creates a clear list of already-executed commands that the LLM can
    easily reference to avoid repeating actions.

    Args:
        attack_context: Dictionary containing successful_attacks and failed_attacks

    Returns:
        Formatted string listing executed commands, or empty string if none
    """
    executed = []

    for attack in attack_context.get("successful_attacks", []):
        if attack.get("type") == "shell":
            cmd = attack.get("command", "")
            target = attack.get("target", "")
            executed.append(f"- shell: {cmd} (target: {target})")
        else:
            exec_type = attack.get("type", "task")
            name = attack.get("name", "")
            targets = attack.get("targets", [])
            opts = attack.get("opts", {})
            opts_str = ", ".join(f"{k}={v}" for k, v in opts.items()) if opts else ""
            targets_str = ", ".join(targets) if targets else ""
            if opts_str:
                executed.append(f"- {exec_type}: {name} on [{targets_str}] with {{{opts_str}}}")
            else:
                executed.append(f"- {exec_type}: {name} on [{targets_str}]")

    for attack in attack_context.get("failed_attacks", []):
        if isinstance(attack, str):
            # Legacy string format - just show the error
            executed.append(f"- (FAILED): {attack}")
        elif attack.get("type") == "shell":
            cmd = attack.get("command", "")
            executed.append(f"- shell (FAILED): {cmd}")
        elif attack.get("type") == "error":
            error = attack.get("error", "unknown error")
            executed.append(f"- (ERROR): {error}")
        else:
            exec_type = attack.get("type", "task")
            name = attack.get("name", "")
            targets = attack.get("targets", [])
            targets_str = ", ".join(targets) if targets else ""
            executed.append(f"- {exec_type} (FAILED): {name} on [{targets_str}]")

    if not executed:
        return ""

    return "## ALREADY EXECUTED - DO NOT REPEAT THESE COMMANDS\n" + "\n".join(executed)


def format_attack_summary(attack_context: dict) -> str:
    """Format attack context as a markdown summary.

    Args:
        attack_context: Dictionary containing attack loop state

    Returns:
        Formatted markdown string
    """
    lines = []
    lines.append("## Attack Summary\n")

    # Statistics
    iterations = attack_context.get("iteration", 0)
    successful = attack_context.get("successful_attacks", [])
    failed = attack_context.get("failed_attacks", [])
    validated = attack_context.get("validated_vulns", [])
    targets = attack_context.get("targets", [])

    lines.append("### Statistics\n")
    lines.append(f"- **Iterations:** {iterations}")
    lines.append(f"- **Targets:** {', '.join(targets) if targets else 'None'}")
    lines.append(f"- **Successful executions:** {len(successful)}")
    lines.append(f"- **Failed executions:** {len(failed)}")
    lines.append(f"- **Validated vulnerabilities:** {len(validated)}")
    lines.append("")

    # Successful attacks
    if successful:
        lines.append("### Executed Commands\n")
        for i, attack in enumerate(successful, 1):
            attack_type = attack.get("type", "unknown")
            if attack_type == "shell":
                cmd = attack.get("command", "")
                target = attack.get("target", "")
                lines.append(f"{i}. **Shell:** `{cmd}`")
                if target:
                    lines.append(f"   - Target: {target}")
            else:
                name = attack.get("name", "")
                attack_targets = attack.get("targets", [])
                result_count = attack.get("result_count", 0)
                lines.append(f"{i}. **{attack_type.capitalize()}:** `{name}`")
                lines.append(f"   - Targets: {', '.join(attack_targets) if attack_targets else 'None'}")
                lines.append(f"   - Results: {result_count}")
        lines.append("")

    # Validated vulnerabilities
    if validated:
        lines.append("### Validated Vulnerabilities\n")
        for vuln in validated:
            name = vuln.get("name", "Unknown")
            severity = vuln.get("severity", "unknown")
            target = vuln.get("target", "")
            lines.append(f"- **{name}** ({severity})")
            if target:
                lines.append(f"  - Target: {target}")
        lines.append("")

    # Failed attacks
    if failed:
        lines.append("### Failed Executions\n")
        for attack in failed:
            if isinstance(attack, str):
                lines.append(f"- {attack}")
            elif attack.get("type") == "error":
                error = attack.get("error", "unknown error")
                lines.append(f"- Error: {error}")
            else:
                attack_type = attack.get("type", "unknown")
                name = attack.get("name", "")
                lines.append(f"- {attack_type}: {name}")
        lines.append("")

    return "\n".join(lines)


def generate_attack_summary_with_llm(
    attack_context: dict,
    model: str,
    api_base: str = None,
    temperature: float = 0.5,
) -> str:
    """Generate a comprehensive attack summary using LLM.

    Args:
        attack_context: Dictionary containing attack loop state
        model: LLM model to use
        api_base: Optional API base URL
        temperature: LLM temperature

    Returns:
        Formatted markdown summary from LLM
    """
    targets = attack_context.get("targets", [])
    successful = attack_context.get("successful_attacks", [])

    # Format executed commands
    executed_lines = []
    for attack in successful:
        attack_type = attack.get("type", "unknown")
        if attack_type == "shell":
            cmd = attack.get("command", "")
            executed_lines.append(f"- Shell: `{cmd}`")
        else:
            name = attack.get("name", "")
            attack_targets = attack.get("targets", [])
            executed_lines.append(f"- {attack_type}: `{name}` on {', '.join(attack_targets)}")

    # Collect all findings from successful attacks
    findings_lines = []
    for attack in successful:
        output = attack.get("output", "")
        if output and output != "No findings available.":
            attack_type = attack.get("type", "unknown")
            name = attack.get("name", "")
            findings_lines.append(f"### {attack_type}: {name}")
            # Truncate very long outputs
            if len(output) > 3000:
                output = output[:3000] + "\n... (truncated)"
            findings_lines.append(output)
            findings_lines.append("")

    # Build prompt
    prompt = PROMPT_ATTACK_FINAL_SUMMARY.format(
        targets=", ".join(targets),
        executed_commands="\n".join(executed_lines) if executed_lines else "None",
        findings="\n".join(findings_lines) if findings_lines else "No findings captured.",
    )

    try:
        response = get_llm_response(
            prompt=prompt,
            model=model,
            system_prompt="You are a penetration testing expert providing actionable security summaries.",
            temperature=temperature,
            api_base=api_base,
            max_tokens=2000,
        )
        return response
    except Exception as e:
        logger.warning(f"Failed to generate LLM summary: {e}")
        # Fall back to basic summary
        return format_attack_summary(attack_context)


def _is_ci():
    """Check if running in CI environment."""
    return any(
        os.environ.get(var)
        for var in (
            "CI",
            "CONTINUOUS_INTEGRATION",
            "GITHUB_ACTIONS",
            "GITLAB_CI",
            "JENKINS_URL",
            "BUILDKITE",
        )
    )


TOOL_RATE_FLAGS = {
    'nuclei': '-rl {rate}',
    'httpx': '-rl {rate}',
    'nmap': '--max-rate {rate}',
    'ffuf': '-rate {rate}',
    'feroxbuster': '--rate-limit {rate}',
    'gobuster': '--delay {delay}ms',
    'dirsearch': '--delay {delay}',
    'sqlmap': '--delay {delay}',
}


def add_rate_limit(command: str, rate: int) -> str:
    """Add rate limit to command based on tool."""
    if rate <= 0:
        return command
    for tool, flag_template in TOOL_RATE_FLAGS.items():
        if f'secator x {tool}' in command or f' {tool} ' in command:
            # Check if rate flag already present
            flag_prefix = flag_template.split()[0]
            if flag_prefix in command:
                return command

            # Calculate delay for tools that use delay instead of rate
            delay = max(1, int(1000 / rate)) if 'delay' in flag_template else rate
            flag = flag_template.format(rate=rate, delay=delay)

            return f"{command} {flag}"

    return command


def check_action_safety(
    action: dict,
    auto_yes: bool,
    in_ci: bool
) -> Tuple[bool, str]:
    """Check if action is safe to run, prompt if needed.

    Returns:
        tuple: (should_run: bool, modified_command: str)
    """
    destructive = action.get('destructive', False)
    aggressive = action.get('aggressive', False)
    command = action.get('command', '')

    # Auto-approve if --yes flag or CI environment
    if auto_yes or in_ci:
        return True, command

    # Non-destructive, non-aggressive: auto-approve
    if not destructive and not aggressive:
        return True, command

    # Handle destructive actions
    if destructive:
        from secator.rich import console
        console.print(f"[bold red]⚠ Destructive action:[/] {command}")
        console.print(f"[dim]Reasoning: {action.get('reasoning', 'N/A')}[/]")

        if not confirm_with_timeout("Execute this destructive action?", default=False):
            return False, command

    # Handle aggressive actions
    if aggressive:
        from secator.rich import console
        console.print(f"[bold orange1]⚠ Aggressive action (may trigger detection):[/] {command}")

        choice = _prompt_aggressive_action()

        if choice == 'skip':
            return False, command
        elif choice == 'limit':
            import click
            rate_limit = click.prompt("Rate limit (requests/sec)", type=int, default=10)
            command = add_rate_limit(command, rate_limit)
            return True, command
        # else: 'run' - continue as-is

    return True, command


def _prompt_aggressive_action() -> str:
    """Prompt user for aggressive action handling."""
    import click
    from secator.rich import console

    console.print("[R]un as-is / [S]kip / [L]imit rate: ", end='')

    while True:
        choice = click.getchar().lower()
        if choice == 'r':
            console.print('Run')
            return 'run'
        elif choice == 's':
            console.print('Skip')
            return 'skip'
        elif choice == 'l':
            console.print('Limit')
            return 'limit'


def confirm_with_timeout(message, default=True, timeout=None):
    """Prompt user with optional timeout."""
    if timeout is None:
        timeout = CONFIG.runners.prompt_timeout

    if timeout and timeout > 0:

        def timeout_handler(signum, frame):
            raise TimeoutError("Prompt timeout")

        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout)
        try:
            result = click.confirm(message, default=default)
        except (TimeoutError, KeyboardInterrupt):
            from secator.rich import console

            console.print(
                rf"\n\[[bold red]AI[/]] [bold red]Prompt timed out after {timeout}s, skipping...[/]"
            )
            result = False
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
        return result
    else:
        return click.confirm(message, default=default)


# PII patterns for detection and encryption
# Order matters: more specific patterns should come before general ones
PII_PATTERNS = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    ),
    "phone": re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(
        r"\b(?:4[0-9]{3}|5[1-5][0-9]{2}|6(?:011|5[0-9]{2})|3[47][0-9]{2})[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b"
    ),
    "api_key": re.compile(
        r'\b(?:api[_-]?key|token|secret|password|passwd|pwd)\s*[:=]\s*["\']?[\w-]{16,}["\']?',
        re.I,
    ),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    "private_key": re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    ),
    "aws_key": re.compile(r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
    # Hostname/domain pattern - matches domains like example.com, sub.example.co.uk
    # Placed last to avoid matching parts of URLs/emails that were already encrypted
    "host": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
    ),
}


class SensitiveDataEncryptor:
    """Encrypt sensitive data using SHA-256 hashing with salt."""

    def __init__(
        self, salt: str = "secator_pii_salt", custom_patterns: List[str] = None
    ):
        self.salt = salt
        self.pii_map: Dict[str, str] = {}  # placeholder -> original
        self.hash_map: Dict[str, str] = {}  # bare hash -> original (for LLM mistakes)
        self.custom_patterns: List[re.Pattern] = []

        # Compile custom patterns (can be literal strings or regexes)
        if custom_patterns:
            for pattern in custom_patterns:
                pattern = pattern.strip()
                if not pattern or pattern.startswith("#"):
                    continue  # Skip empty lines and comments
                try:
                    # Try to compile as regex first
                    self.custom_patterns.append(re.compile(pattern))
                except re.error:
                    # If invalid regex, escape and use as literal string
                    self.custom_patterns.append(re.compile(re.escape(pattern)))

    def _hash_value(self, value: str, pii_type: str) -> str:
        """Hash a sensitive value and return a placeholder."""
        hash_input = f"{self.salt}:{pii_type}:{value}"
        hash_value = hashlib.sha256(hash_input.encode()).hexdigest()[:12]
        placeholder = f"[{pii_type.upper()}:{hash_value}]"
        self.pii_map[placeholder] = value
        self.hash_map[hash_value] = value  # Also store bare hash for fallback
        return placeholder

    def encrypt(self, text: str) -> str:
        """Encrypt all sensitive data in text, returning sanitized version."""
        if not text:
            return text

        result = text

        # Apply custom patterns first (higher priority)
        for i, pattern in enumerate(self.custom_patterns):
            for match in pattern.finditer(result):
                original = match.group()
                placeholder = self._hash_value(original, f"custom_{i}")
                result = result.replace(original, placeholder)

        # Apply built-in PII patterns
        for pii_type, pattern in PII_PATTERNS.items():
            for match in pattern.finditer(result):
                original = match.group()
                placeholder = self._hash_value(original, pii_type)
                result = result.replace(original, placeholder)

        return result

    def decrypt(self, text: str) -> str:
        """Restore original sensitive values from placeholders."""
        result = text
        # First replace full placeholders (e.g., [HOST:a07963bdcb1f])
        for placeholder, original in self.pii_map.items():
            result = result.replace(placeholder, original)
        # Then replace bare hashes (e.g., a07963bdcb1f) that LLM might extract incorrectly
        for hash_value, original in self.hash_map.items():
            result = result.replace(hash_value, original)
        return result


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


def load_sensitive_patterns(file_path: str) -> List[str]:
    """Load sensitive patterns from a file (one pattern per line)."""
    patterns = []
    try:
        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(line)
    except FileNotFoundError:
        logger.warning(f"Sensitive patterns file not found: {file_path}")
    except Exception as e:
        logger.warning(f"Error loading sensitive patterns: {e}")
    return patterns


def _truncate(text: str, max_length: int = 2000) -> str:
    """Truncate text to max_length, adding indicator if truncated."""
    if not text or len(text) <= max_length:
        return text
    return text[:max_length] + "\n... (truncated)"


def _strip_json_from_response(text: str) -> str:
    """Strip JSON blocks from response, keeping only the text/reasoning."""
    if not text:
        return text

    # Remove JSON code blocks first (both objects and arrays)
    text = re.sub(r"```(?:json)?\s*\{[^`]*\}\s*```", "", text, flags=re.DOTALL)
    text = re.sub(r"```(?:json)?\s*\[[^`]*\]\s*```", "", text, flags=re.DOTALL)

    # Find and remove JSON arrays and objects with proper bracket/brace matching
    result = []
    i = 0
    while i < len(text):
        # Handle JSON arrays
        if text[i] == "[":
            # Check if this looks like an action JSON array (has "action" key nearby)
            lookahead = text[i : i + 100]
            if '"action"' in lookahead:
                # Find matching closing bracket
                bracket_count = 0
                while i < len(text):
                    if text[i] == "[":
                        bracket_count += 1
                    elif text[i] == "]":
                        bracket_count -= 1
                        if bracket_count == 0:
                            i += 1
                            break
                    i += 1
                # JSON array removed, continue
                continue
        # Handle JSON objects
        elif text[i] == "{":
            # Check if this looks like an action JSON (has "action" key nearby)
            lookahead = text[i : i + 50]
            if '"action"' in lookahead:
                # Find matching closing brace
                brace_count = 0
                while i < len(text):
                    if text[i] == "{":
                        brace_count += 1
                    elif text[i] == "}":
                        brace_count -= 1
                        if brace_count == 0:
                            i += 1
                            break
                    i += 1
                # JSON block removed, continue
                continue
        result.append(text[i])
        i += 1

    text = "".join(result)

    # Clean up extra whitespace
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = text.strip()

    return text if text else ""


def format_results_for_llm(results: List[Any]) -> str:
    """Format secator results into a structured prompt for the LLM."""
    if not results:
        return "No previous results available."

    formatted = []
    result_types: Dict[str, List] = {}

    # Get valid finding type names for filtering
    finding_types_tuple = tuple(FINDING_TYPES)
    finding_type_names = {ft.get_name() for ft in FINDING_TYPES}

    for result in results:
        # Handle OutputType instances
        if isinstance(result, finding_types_tuple):
            result_type = getattr(result, "_type", "unknown")
            if result_type not in result_types:
                result_types[result_type] = []
            result_types[result_type].append(result)
        # Handle dictionaries (from workspace/JSON queries)
        elif isinstance(result, dict):
            result_type = result.get("_type", "unknown")
            # Skip non-finding types
            if result_type not in finding_type_names:
                continue
            if result_type not in result_types:
                result_types[result_type] = []
            result_types[result_type].append(result)

    # Return early if no findings after filtering
    if not result_types:
        return "No findings available."

    for rtype, items in result_types.items():
        formatted.append(f"[{rtype.upper()}:{len(items)}]")
        for item in items:
            try:
                if isinstance(item, dict):
                    # Filter out internal fields from dictionary
                    data = {
                        k: v
                        for k, v in item.items()
                        if not k.startswith("_") and v
                    }
                    formatted.append(json.dumps(data, default=str, separators=(',', ':')))
                elif hasattr(item, "__dict__"):
                    # Filter out internal fields, compact JSON output
                    data = {
                        k: v
                        for k, v in asdict(item).items()
                        if not k.startswith("_") and v
                    }
                    formatted.append(json.dumps(data, default=str, separators=(',', ':')))
                else:
                    formatted.append(str(item))
            except Exception:
                formatted.append(str(item))

    return "\n".join(formatted)


def enrich_vulnerability_with_poc(
    vuln: 'Vulnerability',
    scan_output: str,
    tool_name: str,
    model: str,
    api_base: str = None,
    temperature: float = 0.3,
) -> 'Vulnerability':
    """Ask AI to generate proof of concept for a vulnerability.

    Args:
        vuln: The vulnerability to enrich
        scan_output: The raw scan output for context
        tool_name: Name of the tool that found the vulnerability
        model: LLM model to use
        api_base: Optional API base URL
        temperature: LLM temperature

    Returns:
        Enriched vulnerability with proof_of_concept in extra_data
    """
    try:
        import litellm

        prompt = PROMPT_VULN_PROOF_OF_CONCEPT.format(
            tool_name=tool_name,
            vuln_name=vuln.name,
            severity=vuln.severity,
            target=vuln.matched_at,
            provider=vuln.provider,
            description=vuln.description or "No description provided",
            scan_output=scan_output[:4000],  # Limit output size
        )

        kwargs = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
            "max_tokens": 1000,
        }
        if api_base:
            kwargs["api_base"] = api_base

        response = litellm.completion(**kwargs)
        response_text = response.choices[0].message.content.strip()

        # Parse JSON response - try multiple approaches
        poc_data = None

        # Try direct JSON parse first
        try:
            poc_data = json.loads(response_text)
        except json.JSONDecodeError:
            pass

        # Try to extract from markdown code block
        if poc_data is None:
            # Match code block and extract content between ```json and ```
            code_block_match = re.search(r'```(?:json)?\s*\n?([\s\S]*?)\n?```', response_text)
            if code_block_match:
                try:
                    poc_data = json.loads(code_block_match.group(1).strip())
                except json.JSONDecodeError:
                    pass

        # Try to find JSON object by matching braces
        if poc_data is None and '{' in response_text:
            # Find the first { and try to extract the full JSON object
            start_idx = response_text.find('{')
            if start_idx != -1:
                brace_count = 0
                end_idx = start_idx
                for i in range(start_idx, len(response_text)):
                    if response_text[i] == '{':
                        brace_count += 1
                    elif response_text[i] == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            end_idx = i + 1
                            break
                if end_idx > start_idx:
                    try:
                        poc_data = json.loads(response_text[start_idx:end_idx])
                    except json.JSONDecodeError:
                        pass

        # Merge into extra_data
        if not vuln.extra_data:
            vuln.extra_data = {}

        if poc_data:
            vuln.extra_data["proof_of_concept"] = poc_data.get("proof_of_concept", "")
            vuln.extra_data["reproduction_steps"] = poc_data.get("reproduction_steps", [])
            vuln.extra_data["impact"] = poc_data.get("impact", "")
            vuln.extra_data["remediation"] = poc_data.get("remediation", "")
            vuln.extra_data["ai_enriched"] = True
        else:
            # If not valid JSON, store raw response as proof
            vuln.extra_data["proof_of_concept"] = response_text
            vuln.extra_data["ai_enriched"] = True

    except Exception as e:
        logger.warning(f"Failed to enrich vulnerability with PoC: {e}")
        if not vuln.extra_data:
            vuln.extra_data = {}
        vuln.extra_data["poc_error"] = str(e)

    return vuln


def batch_enrich_vulnerabilities_with_poc(
    vulnerabilities: List['Vulnerability'],
    scan_output: str,
    tool_name: str,
    model: str,
    api_base: str = None,
    temperature: float = 0.3,
) -> List['Vulnerability']:
    """Ask AI to generate proof of concept for multiple vulnerabilities in a single call.

    Args:
        vulnerabilities: List of vulnerabilities to enrich
        scan_output: The raw scan output for context
        tool_name: Name of the tool that found the vulnerabilities
        model: LLM model to use
        api_base: Optional API base URL
        temperature: LLM temperature

    Returns:
        List of enriched vulnerabilities with proof_of_concept in extra_data
    """
    if not vulnerabilities:
        return vulnerabilities

    # If only one vulnerability, use the single enrichment function
    if len(vulnerabilities) == 1:
        return [enrich_vulnerability_with_poc(
            vulnerabilities[0], scan_output, tool_name, model, api_base, temperature
        )]

    try:
        import litellm

        # Build vulnerability list for the prompt
        vuln_lines = []
        for i, vuln in enumerate(vulnerabilities):
            vuln_lines.append(
                f"[{i}] {vuln.name}\n"
                f"    Severity: {vuln.severity}\n"
                f"    Target: {vuln.matched_at}\n"
                f"    Provider: {vuln.provider}\n"
                f"    Description: {vuln.description or 'No description'}"
            )

        prompt = PROMPT_VULN_BATCH_PROOF_OF_CONCEPT.format(
            vulnerabilities_list="\n\n".join(vuln_lines),
            scan_output=scan_output[:6000],  # Larger limit for batch
        )

        kwargs = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
            "max_tokens": 2000 + (500 * len(vulnerabilities)),  # Scale with count
        }
        if api_base:
            kwargs["api_base"] = api_base

        response = litellm.completion(**kwargs)
        response_text = response.choices[0].message.content.strip()

        # Parse JSON array response
        poc_list = None

        # Try direct JSON parse first
        try:
            poc_list = json.loads(response_text)
        except json.JSONDecodeError:
            pass

        # Try to extract from markdown code block
        if poc_list is None:
            code_block_match = re.search(r'```(?:json)?\s*\n?([\s\S]*?)\n?```', response_text)
            if code_block_match:
                try:
                    poc_list = json.loads(code_block_match.group(1).strip())
                except json.JSONDecodeError:
                    pass

        # Try to find JSON array by matching brackets
        if poc_list is None and '[' in response_text:
            start_idx = response_text.find('[')
            if start_idx != -1:
                bracket_count = 0
                end_idx = start_idx
                for i in range(start_idx, len(response_text)):
                    if response_text[i] == '[':
                        bracket_count += 1
                    elif response_text[i] == ']':
                        bracket_count -= 1
                        if bracket_count == 0:
                            end_idx = i + 1
                            break
                if end_idx > start_idx:
                    try:
                        poc_list = json.loads(response_text[start_idx:end_idx])
                    except json.JSONDecodeError:
                        pass

        # Enrich vulnerabilities with parsed data
        if poc_list and isinstance(poc_list, list):
            # Create lookup by id
            poc_by_id = {}
            for poc in poc_list:
                if isinstance(poc, dict) and 'id' in poc:
                    poc_by_id[poc['id']] = poc

            for i, vuln in enumerate(vulnerabilities):
                if not vuln.extra_data:
                    vuln.extra_data = {}

                # Try to find by id, fallback to index
                poc_data = poc_by_id.get(i) or (poc_list[i] if i < len(poc_list) else None)

                if poc_data and isinstance(poc_data, dict):
                    vuln.extra_data["proof_of_concept"] = poc_data.get("proof_of_concept", "")
                    vuln.extra_data["reproduction_steps"] = poc_data.get("reproduction_steps", [])
                    vuln.extra_data["impact"] = poc_data.get("impact", "")
                    vuln.extra_data["remediation"] = poc_data.get("remediation", "")
                    vuln.extra_data["ai_enriched"] = True
                else:
                    vuln.extra_data["ai_enriched"] = False
                    vuln.extra_data["poc_error"] = "No PoC data in batch response"
        else:
            # Batch parsing failed, mark all as not enriched
            for vuln in vulnerabilities:
                if not vuln.extra_data:
                    vuln.extra_data = {}
                vuln.extra_data["ai_enriched"] = False
                vuln.extra_data["poc_error"] = "Failed to parse batch response"

    except Exception as e:
        logger.warning(f"Failed to batch enrich vulnerabilities with PoC: {e}")
        for vuln in vulnerabilities:
            if not vuln.extra_data:
                vuln.extra_data = {}
            vuln.extra_data["poc_error"] = str(e)

    return vulnerabilities


def prompt_user_for_continuation() -> Optional[str]:
    """Prompt the user for the next query to continue the attack.

    Returns:
        User's query string or None if they want to stop
    """
    try:
        print()  # New line for better formatting
        user_input = click.prompt(
            click.style("🤖 Run finished. Enter next query (or 'quit' to stop)", fg="cyan"),
            default="",
            show_default=False,
        )
        if user_input.lower() in ('quit', 'exit', 'stop', 'q', ''):
            return None
        return user_input.strip()
    except (click.Abort, EOFError, KeyboardInterrupt):
        return None


def get_output_types_schema() -> str:
    """Generate schema description of output types for LLM."""
    schema_lines = []

    excluded_fields = ['extra_data', 'tags', 'is_false_positive', 'is_acknowledged']
    for output_type in FINDING_TYPES:
        type_name = output_type.get_name()
        type_fields = [
            f.name for f in fields(output_type)
            if not f.name.startswith('_') and f.name not in excluded_fields
        ]
        fields_str = ', '.join(type_fields[:10])  # Limit fields shown
        schema_lines.append(f"- {type_name}: {fields_str}")

    schema_lines.append("\nCommon fields (all types): _type, _source, _context, is_false_positive, tags, extra_data")

    return '\n'.join(schema_lines)


def parse_intent_response(response: str) -> Optional[Dict[str, Any]]:
    """Parse intent analysis response from LLM."""
    # Try direct JSON parse
    try:
        return json.loads(response)
    except json.JSONDecodeError:
        pass

    # Try to extract from code block
    json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(1))
        except json.JSONDecodeError:
            pass

    # Try to find raw JSON object
    json_match = re.search(r'\{[^{}]*"mode"[^{}]*\}', response, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group())
        except json.JSONDecodeError:
            pass

    return None


def analyze_intent(
    prompt: str,
    targets: List[str],
    model: str = 'gpt-4o-mini',
    verbose: bool = False,
    api_base: str = None
) -> Optional[Dict[str, Any]]:
    """Phase 1: Analyze user intent and generate queries."""
    user_message = f"Prompt: {prompt}"
    if targets:
        user_message += f"\nTargets: {', '.join(targets)}"

    system_prompt = PROMPT_INTENT_ANALYSIS.format(
        output_types_schema=get_output_types_schema()
    )

    response = get_llm_response(
        prompt=user_message,
        model=model,
        system_prompt=system_prompt,
        temperature=0.3,
        verbose=verbose,
        api_base=api_base
    )

    if not response:
        return None

    return parse_intent_response(response)


def get_llm_response(
    prompt: str,
    model: str = "gpt-4o-mini",
    system_prompt: str = "",
    temperature: float = 0.7,
    max_tokens: int = 4096,
    max_retries: int = 5,
    initial_delay: float = 1.0,
    verbose: bool = False,
    api_base: str = None,
) -> Optional[str]:
    """Get response from LLM using LiteLLM with exponential backoff for rate limits."""
    try:
        import litellm

        # Suppress debug output unless 'litellm' is in CONFIG.debug
        if "litellm" not in CONFIG.debug:
            litellm.suppress_debug_info = True
            litellm.set_verbose = False
            litellm.json_logs = True
            # Suppress litellm logger debug output
            logging.getLogger("LiteLLM").setLevel(logging.WARNING)
            logging.getLogger("litellm").setLevel(logging.WARNING)
            logging.getLogger("httpx").setLevel(logging.WARNING)

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        # Ensure temperature is a float (CLI may pass it as string)
        temp = float(temperature) if temperature is not None else 0.7

        # Retry loop with exponential backoff for rate limits
        last_exception = None
        for attempt in range(max_retries):
            try:
                response = litellm.completion(
                    model=model,
                    messages=messages,
                    temperature=temp,
                    max_tokens=int(max_tokens),
                    api_base=api_base,
                )

                # Show token usage and cost
                if hasattr(response, 'usage') and response.usage:
                    usage = response.usage
                    prompt_tokens = getattr(usage, 'prompt_tokens', 0)
                    completion_tokens = getattr(usage, 'completion_tokens', 0)
                    total_tokens = getattr(usage, 'total_tokens', 0)

                    # Try to get cost estimate
                    try:
                        cost = litellm.completion_cost(completion_response=response)
                        cost_str = f", cost: ${cost:.4f}" if cost else ""
                    except Exception:
                        cost_str = ""

                    console.print(
                        f"[dim]📊 Tokens: {prompt_tokens} prompt + {completion_tokens} completion = {total_tokens} total{cost_str}[/]"
                    )

                return response.choices[0].message.content
            except litellm.RateLimitError as e:
                last_exception = e
                if attempt < max_retries - 1:
                    delay = initial_delay * (2**attempt)  # Exponential backoff
                    logger.warning(
                        f"Rate limit hit, retrying in {delay:.1f}s (attempt {attempt + 1}/{max_retries})"
                    )
                    time.sleep(delay)
                else:
                    logger.error(f"Rate limit exceeded after {max_retries} retries")
                    raise

        # Should not reach here, but just in case
        if last_exception:
            raise last_exception

    except ImportError:
        raise ImportError("litellm is required. Install with: pip install litellm")
    except Exception as e:
        logger.error(f"LLM error: {e}")
        raise


def parse_secator_command(cmd: str) -> Optional[Dict]:
    """Parse a secator command string into components."""
    # Match: secator [x|w|s] <name> <targets> [options]
    match = re.match(r"secator\s+([xwst])\s+(\S+)\s*(.*)", cmd.strip())
    if not match:
        return None

    runner_type = match.group(1)
    name = match.group(2)
    rest = match.group(3).strip()

    # Parse targets and options
    targets = []
    options = {}

    parts = rest.split()
    i = 0
    while i < len(parts):
        part = parts[i]
        if part.startswith("--"):
            opt_name = part[2:].replace("-", "_")
            if i + 1 < len(parts) and not parts[i + 1].startswith("-"):
                options[opt_name] = parts[i + 1]
                i += 2
            else:
                options[opt_name] = True
                i += 1
        elif part.startswith("-") and len(part) == 2:
            opt_name = part[1:]
            if i + 1 < len(parts) and not parts[i + 1].startswith("-"):
                options[opt_name] = parts[i + 1]
                i += 2
            else:
                options[opt_name] = True
                i += 1
        else:
            targets.append(part)
            i += 1

    return {
        "runner_type": runner_type,
        "name": name,
        "targets": targets,
        "options": options,
    }


def run_secator_task(name: str, targets: List[str], options: Dict = None) -> List[Any]:
    """Run a secator task and return results."""
    from secator.runners import Task

    options = options or {}
    task_cls = Task.get_task_class(name)

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
        **options,
    }

    task_instance = task_cls(targets, **run_opts)
    results = []
    for item in task_instance:
        results.append(item)
    return results


@task()
class ai(PythonRunner):
    """AI-powered penetration testing assistant using LLM."""

    output_types = [Vulnerability, Tag, Info, Warning, Error, AI]
    tags = ["ai", "analysis", "pentest"]
    input_types = []  # Accept any input type
    install_cmd = "pip install litellm"
    default_inputs = ''

    opts = {
        "prompt": {
            "type": str,
            "default": "",
            "short": "p",
            "help": "Natural language prompt or path to a text/markdown file",
        },
        "mode": {
            "type": str,
            "default": "",
            "help": "Force operation mode: summarize, suggest, or attack (auto-detected if not set)",
        },
        "model": {
            "type": str,
            "default": CONFIG.ai.default_model,
            "help": "LLM model to use (via LiteLLM)",
        },
        "intent_model": {
            "type": str,
            "default": CONFIG.ai.intent_model,
            "help": "LLM model for intent analysis (Phase 1). Defaults to --model if not set.",
        },
        'api_base': {
            'type': str,
            'default': CONFIG.ai.api_base,
            'help': 'API base URL for local models (e.g., http://localhost:11434 for Ollama)',
        },
        "sensitive": {
            "is_flag": True,
            "default": True,
            "help": "Encrypt sensitive data (PII, IPs, hosts) before sending to LLM",
        },
        "sensitive_list": {
            "type": str,
            "default": None,
            "help": "File containing custom sensitive patterns to encrypt (one per line, supports regex)",
        },
        "max_iterations": {
            "type": int,
            "default": 10,
            "help": "Maximum attack loop iterations (attack mode only)",
        },
        "temperature": {
            "type": float,
            "default": 0.7,
            "help": "LLM temperature for response generation",
        },
        "dry_run": {
            "is_flag": True,
            "default": False,
            "help": "Show planned actions without executing (attack mode)",
        },
        "run": {
            "is_flag": True,
            "default": False,
            "help": "Execute suggested tasks (suggest mode only)",
        },
        "yes": {
            "is_flag": True,
            "default": False,
            "short": "y",
            "help": "Auto-accept prompts without confirmation",
        },
        "verbose": {
            "is_flag": True,
            "default": False,
            "short": "v",
            "help": "Show verbose LLM debug output",
        },
        "disable_secator": {
            "is_flag": True,
            "default": False,
            "help": "Disable secator runners (task/workflow/scan), use only shell commands",
        },
        "dangerous": {
            "is_flag": True,
            "default": False,
            "help": "Allow AI to run ANY shell command (DANGEROUS - use with caution)",
        },
    }

    def __init__(self, inputs=[], **run_opts):
        # Store results before parent init resets them
        self._previous_results = run_opts.get("results", [])
        super().__init__(inputs, **run_opts)

    def yielder(self) -> Generator:
        """Execute AI task based on selected mode."""
        # Check for litellm
        try:
            import litellm  # noqa: F401
        except ImportError:
            yield Error(
                message="litellm is required. Install with: pip install litellm"
            )
            return

        # Extract options
        prompt_input = self.run_opts.get("prompt", "")
        prompt, prompt_from_file, prompt_is_markdown = load_prompt_from_file_or_text(prompt_input)

        # Always show the user's prompt if one was provided
        if prompt:
            if prompt_from_file:
                yield Info(message=f"Loaded prompt from file: {prompt_input}")
            # Display the prompt content with markdown rendering
            yield AI(content=prompt, ai_type='prompt')

        mode_override = self.run_opts.get("mode", "")
        model = self.run_opts.get("model")
        intent_model = self.run_opts.get("intent_model") or model
        api_base = self.run_opts.get("api_base")
        sensitive = self.run_opts.get("sensitive", True)
        sensitive_list = self.run_opts.get("sensitive_list")
        verbose = self.run_opts.get("verbose", False)

        # Show model info
        model_info = f"Using model: {model}"
        if api_base:
            model_info += f" (API: {api_base})"
        yield Info(message=model_info)

        # Get workspace context
        workspace_id = self.context.get("workspace_id") if self.context else None

        # Targets are from self.inputs
        targets = self.inputs

        # Phase 1: Intent Analysis
        queries = [{}]
        use_workspace = False  # Default to NOT using workspace unless explicitly requested
        if prompt and not mode_override:
            yield Info(message=f"Analyzing intent using {intent_model}...")
            intent = analyze_intent(
                prompt=prompt,
                targets=targets,
                model=intent_model,
                verbose=verbose,
                api_base=api_base
            )
            if intent:
                mode = intent.get("mode", "summarize")
                use_workspace = intent.get("use_workspace", False)
                queries = intent.get("queries", [{}])
                yield Info(message=f"Mode: {mode}, Use workspace: {use_workspace}, Queries: {len(queries)}")
            else:
                yield Warning(message="Could not analyze intent, defaulting to summarize mode")
                mode = "summarize"
        else:
            mode = mode_override or "summarize"

        # Get results from previous runs
        results = self._previous_results or self.results

        # Fetch workspace results if workspace_id available and use_workspace is True
        if workspace_id and use_workspace:
            from secator.query import QueryEngine
            engine = QueryEngine(workspace_id, context=self.context)

            # Map backend names to user-friendly display
            backend_display = {
                "api": "remote API",
                "mongodb": "MongoDB",
                "json": "local JSON",
            }
            backend_name = backend_display.get(engine.backend.name, engine.backend.name)
            # For JSON backend, show the path being searched
            if engine.backend.name == "json":
                from secator.query.json import JsonBackend
                if isinstance(engine.backend, JsonBackend):
                    workspace_path = engine.backend._get_workspace_path()
                    yield Info(message=f"Querying workspace '{workspace_id}' from {workspace_path}")
                    if not workspace_path.exists():
                        yield Warning(message=f"Workspace path does not exist: {workspace_path}")
                        # Show available workspaces
                        reports_dir = engine.backend.reports_dir
                        if reports_dir.exists():
                            available = [d.name for d in reports_dir.iterdir() if d.is_dir()]
                            if available:
                                yield Info(message=f"Available workspaces: {', '.join(available)}")
            else:
                yield Info(message=f"Querying workspace {workspace_id} ({backend_name})...")
            if not queries:
                queries = [{}]
            for query in queries:
                # Format query for display
                query_str = json.dumps(query) if query else "{}"
                # Exclude _context field to reduce data size
                query_results = engine.search(query, limit=100, exclude_fields=["_context"])
                results.extend(query_results)
                yield Info(message=f"Query: {query_str} -> {len(query_results)} results")

            # Deduplicate by _uuid
            seen_uuids = set()
            unique_results = []
            for r in results:
                uuid = r.get("_uuid") if isinstance(r, dict) else getattr(r, "_uuid", None)
                if uuid is None:
                    uuid = id(r)
                if uuid not in seen_uuids:
                    seen_uuids.add(uuid)
                    unique_results.append(r)
            results = unique_results

            yield Info(message=f"Total: {len(results)} unique results from workspace")

        # Check if we have enough context to proceed
        # We need at least targets or results (prompt alone is not enough)
        if not results and not targets:
            yield Warning(
                message="No results or targets available for AI analysis. Provide targets as input or use a workspace with results."
            )
            return

        yield Info(message=f"Starting AI analysis in '{mode}' mode using {model}")

        # Load custom sensitive patterns if provided
        custom_patterns = []
        if sensitive_list:
            custom_patterns = load_sensitive_patterns(sensitive_list)
            if custom_patterns:
                yield Info(
                    message=f"Loaded {len(custom_patterns)} custom sensitive patterns"
                )

        # Initialize sensitive data encryptor
        encryptor = SensitiveDataEncryptor(custom_patterns=custom_patterns)

        # Format context for LLM
        context_text = ""
        if results:
            context_text = format_results_for_llm(results)
            if sensitive:
                context_text = encryptor.encrypt(context_text)
                yield Info(
                    message=f"Sensitive data encrypted: {len(encryptor.pii_map)} values masked"
                )

        if targets:
            targets_text = f"\n\n## Targets\n{', '.join(targets)}"
            if sensitive:
                targets_text = encryptor.encrypt(targets_text)
            context_text += targets_text

        # Route to appropriate mode handler
        if mode == "summarize":
            yield from self._mode_summarize(
                context_text, model, encryptor, results, targets, api_base
            )
        elif mode == "suggest":
            yield from self._mode_suggest(
                context_text, model, encryptor, results, targets, api_base
            )
        elif mode == "attack":
            yield from self._mode_attack(
                context_text, model, encryptor, results, targets, api_base, use_workspace
            )
        else:
            yield Error(
                message=f"Unknown mode: {mode}. Use: summarize, suggest, or attack"
            )

    def _mode_summarize(
        self,
        context_text: str,
        model: str,
        encryptor: SensitiveDataEncryptor,
        results: List[Any],
        targets: List[str],
        api_base: str = None,
    ) -> Generator:
        """Summarize results and identify attack paths."""
        custom_prompt_input = self.run_opts.get("prompt", "")
        custom_prompt, prompt_from_file, prompt_is_markdown = load_prompt_from_file_or_text(custom_prompt_input)
        if prompt_from_file:
            yield Info(message=f"Loaded prompt from file: {custom_prompt_input}")

        # If no results but have targets, suggest initial recon
        if not results and targets:
            yield Info(
                message="No previous results. Providing initial reconnaissance suggestions."
            )
            prompt = PROMPT_ANALYZE_TARGETS.format(targets=", ".join(targets))
            system_prompt = get_system_prompt("initial_recon")
        else:
            custom_section = f"\n\n## Additional Instructions\n{custom_prompt}" if custom_prompt else ""
            prompt = PROMPT_ANALYZE_RESULTS.format(
                targets=", ".join(targets),
                context=context_text,
                custom_prompt=custom_section
            )
            system_prompt = get_system_prompt("summarize")

        verbose = self.run_opts.get("verbose", False)

        # Show the full prompt only in verbose mode
        if verbose:
            if prompt_is_markdown and custom_prompt:
                formatted_custom = format_prompt_for_display(custom_prompt, is_markdown=True)
                yield AI(content=f"{prompt}\n[CUSTOM PROMPT]{formatted_custom}", ai_type='prompt')
            else:
                yield AI(content=prompt, ai_type='prompt')

        try:
            response = get_llm_response(
                prompt=prompt,
                model=model,
                system_prompt=system_prompt,
                temperature=float(self.run_opts.get("temperature", 0.7)),
                api_base=api_base,
            )

            # Decrypt sensitive data in response
            if self.run_opts.get("sensitive", True):
                response = encryptor.decrypt(response)

            # Show AI response with markdown rendering
            yield AI(
                content=response,
                ai_type='summary',
                mode='summarize',
                model=model,
            )

        except Exception as e:
            yield Error(message=f"Summarize failed: {str(e)}")

    def _mode_suggest(
        self,
        context_text: str,
        model: str,
        encryptor: SensitiveDataEncryptor,
        results: List[Any],
        targets: List[str],
        api_base: str = None,
    ) -> Generator:
        """Suggest next secator tasks to run."""
        run_suggestions = self.run_opts.get("run", False)
        auto_yes = self.run_opts.get("yes", False)
        in_ci = _is_ci()
        verbose = self.run_opts.get("verbose", False)
        custom_prompt_input = self.run_opts.get("prompt", "")
        custom_prompt, prompt_from_file, prompt_is_markdown = load_prompt_from_file_or_text(custom_prompt_input)
        if prompt_from_file:
            yield Info(message=f"Loaded prompt from file: {custom_prompt_input}")

        # Build prompt based on whether we have results
        if not results and targets:
            prompt = PROMPT_SUGGEST_TARGETS.format(targets=", ".join(targets))
            system_prompt = get_system_prompt("initial_recon")
        else:
            custom_section = f"\n\n## Additional Instructions\n{custom_prompt}" if custom_prompt else ""
            prompt = PROMPT_SUGGEST_RESULTS.format(
                targets=", ".join(targets),
                context=context_text,
                custom_prompt=custom_section
            )
            system_prompt = get_system_prompt("suggest")

        # Show the full prompt only in verbose mode
        if verbose:
            if prompt_is_markdown and custom_prompt:
                formatted_custom = format_prompt_for_display(custom_prompt, is_markdown=True)
                yield AI(content=f"{prompt}\n[CUSTOM PROMPT]{formatted_custom}", ai_type='prompt')
            else:
                yield AI(content=prompt, ai_type='prompt')

        try:
            response = get_llm_response(
                prompt=prompt,
                model=model,
                system_prompt=system_prompt,
                temperature=float(self.run_opts.get('temperature', 0.7)),
                api_base=api_base,
            )

            # Decrypt sensitive data in response
            if self.run_opts.get("sensitive", True):
                response = encryptor.decrypt(response)

            # Extract suggested commands
            commands = self._extract_commands(response)

            # Show AI response with markdown rendering
            yield AI(
                content=response,
                ai_type='suggestion',
                mode='suggest',
                model=model,
                extra_data={"suggested_commands": commands},
            )

            # Yield individual command suggestions
            for cmd in commands:
                yield Tag(
                    name="suggested_command",
                    value=cmd,
                    match="suggest",
                    category="action",
                )

            # Run suggestions if requested
            if run_suggestions and commands:
                yield Info(message=f"Preparing to run {len(commands)} suggested tasks")

                for cmd in commands:
                    parsed = parse_secator_command(cmd)
                    if not parsed:
                        yield Warning(message=f"Could not parse command: {cmd}")
                        continue

                    if parsed["runner_type"] != "x":
                        yield Warning(
                            message=f"Only task execution (secator x) is supported: {cmd}"
                        )
                        continue

                    task_name = parsed["name"]
                    task_targets = parsed["targets"] or targets
                    task_options = parsed["options"]

                    # Confirm with user unless auto-yes
                    if auto_yes or in_ci:
                        should_run = True
                    else:
                        should_run = confirm_with_timeout(
                            f"Run: secator x {task_name} {' '.join(task_targets)}?",
                            default=True,
                        )

                    if should_run:
                        yield Info(
                            message=f"Running: secator x {task_name} {' '.join(task_targets)}"
                        )
                        try:
                            task_results = run_secator_task(
                                task_name, task_targets, task_options
                            )
                            for result in task_results:
                                yield result
                            yield Info(
                                message=f"Task {task_name} completed with {len(task_results)} results"
                            )
                        except ValueError as e:
                            yield Error(
                                message=f"Task not found: {task_name} - {str(e)}"
                            )
                        except Exception as e:
                            yield Error(message=f"Task {task_name} failed: {str(e)}")
                    else:
                        yield Info(message=f"Skipped: {cmd}")

        except Exception as e:
            yield Error(message=f"Suggest failed: {str(e)}")

    def _mode_attack(
        self,
        context_text: str,
        model: str,
        encryptor: SensitiveDataEncryptor,
        results: List[Any],
        targets: List[str],
        api_base: str = None,
        use_workspace: bool = False,
    ) -> Generator:
        """Execute reactive attack loop to exploit vulnerabilities."""
        max_iterations = int(self.run_opts.get("max_iterations", 10))
        dry_run = self.run_opts.get("dry_run", False)
        verbose = self.run_opts.get("verbose", False)
        temperature = float(self.run_opts.get("temperature", 0.7))
        disable_secator = self.run_opts.get("disable_secator", False)
        custom_prompt_input = self.run_opts.get("prompt", "")
        custom_prompt, prompt_from_file, prompt_is_markdown = load_prompt_from_file_or_text(custom_prompt_input)
        if prompt_from_file:
            yield Info(message=f"Loaded prompt from file: {custom_prompt_input}")
            # Show formatted markdown content
            if prompt_is_markdown:
                formatted_custom = format_prompt_for_display(custom_prompt, is_markdown=True)
                yield Info(message=f"[CUSTOM PROMPT]{formatted_custom}")

        yield Info(
            message=f"Starting attack mode (max {max_iterations} iterations, dry_run={dry_run})"
        )

        # Build attack context
        attack_context = {
            "iteration": 0,
            "successful_attacks": [],
            "failed_attacks": [],
            "validated_vulns": [],
            "targets": targets,
        }

        # Track enriched vulnerabilities to avoid duplicates
        enriched_vuln_ids = set()

        # Encrypt targets for prompts if sensitive data encryption enabled
        sensitive = self.run_opts.get("sensitive", True)
        targets_str = ", ".join(targets)
        if sensitive:
            targets_str = encryptor.encrypt(targets_str)

        # Create custom prompt suffix to include in all prompts
        # Encrypt if sensitive mode enabled for consistency with executed commands
        custom_prompt_suffix = ""
        if custom_prompt:
            prompt_text = custom_prompt
            if sensitive:
                prompt_text = encryptor.encrypt(prompt_text)
            custom_prompt_suffix = (
                f"\n\n## IMPORTANT - User Instructions (MUST FOLLOW)\n{prompt_text}"
            )

        # Initial prompt - if no workspace data requested, skip "Current Findings" as it only contains execution info
        if not use_workspace:
            prompt = PROMPT_ATTACK_START_NO_RESULTS.format(targets=targets_str) + custom_prompt_suffix
        elif not results:
            prompt = PROMPT_ATTACK_START_NO_RESULTS.format(targets=targets_str) + custom_prompt_suffix
        else:
            prompt = PROMPT_ATTACK_START_WITH_RESULTS.format(
                context=context_text,
                targets=targets_str
            ) + custom_prompt_suffix

        # Show master prompt (system prompt) in verbose mode - only once at start
        if verbose:
            system_prompt = get_system_prompt("attack", disable_secator=disable_secator)
            yield AI(content=system_prompt, ai_type='prompt')

        if disable_secator:
            yield Info(message="Secator runners disabled - using shell commands only")

        for iteration in range(max_iterations):
            attack_context["iteration"] = iteration + 1
            yield Info(message=f"Attack iteration {iteration + 1}/{max_iterations}")

            try:
                # Show the user prompt only in verbose mode
                if verbose:
                    yield AI(content=prompt, ai_type='prompt')

                response = get_llm_response(
                    prompt=prompt,
                    model=model,
                    system_prompt=get_system_prompt("attack", disable_secator=disable_secator),
                    temperature=temperature,
                    api_base=api_base,
                )

                # Decrypt sensitive data
                if self.run_opts.get("sensitive", True):
                    response = encryptor.decrypt(response)

                # Parse actions from response (now returns list)
                actions = self._parse_attack_actions(response)

                # Show AI response with markdown rendering
                # In verbose mode show full response, otherwise strip JSON
                if verbose:
                    response_display = response
                else:
                    response_display = _strip_json_from_response(response)

                if response_display:
                    yield AI(
                        content=response_display,
                        ai_type='response',
                        mode='attack',
                        model=model,
                        extra_data={"iteration": iteration + 1},
                    )

                if not actions:
                    yield Warning(message="Could not parse actions from LLM response")
                    # Resend previous context with the invalid response so LLM can fix it
                    executed_cmds = format_executed_commands(attack_context)
                    encrypted_response = response[:2000]
                    if sensitive:
                        encrypted_response = encryptor.encrypt(encrypted_response)
                        if executed_cmds:
                            executed_cmds = encryptor.encrypt(executed_cmds)
                    prompt = PROMPT_ATTACK_INVALID_JSON.format(
                        response=encrypted_response,
                        targets=targets_str,
                        executed_commands=executed_cmds,
                        user_instructions=custom_prompt_suffix
                    )
                    continue

                # Separate terminal actions (complete, stop) from executable actions
                terminal_action = None
                executable_actions = []
                for action in actions:
                    action_type = action.get("action", "")
                    if action_type in ("complete", "stop"):
                        terminal_action = action
                        break  # Terminal action stops processing
                    else:
                        executable_actions.append(action)

                # If we have a terminal action with no executable actions, handle it
                if terminal_action and not executable_actions:
                    action_type = terminal_action.get("action", "")
                    if action_type == "complete":
                        yield Info(message="Attack loop completed")
                        yield Info(message="Generating comprehensive attack summary...")
                        full_summary = generate_attack_summary_with_llm(
                            attack_context,
                            model=model,
                            api_base=api_base,
                            temperature=temperature,
                        )
                        yield AI(
                            content=full_summary,
                            ai_type='attack_summary',
                            mode='attack',
                            model=model,
                        )

                        user_query = prompt_user_for_continuation()
                        if user_query is None:
                            yield Info(message="User chose to stop. Ending attack loop.")
                            break

                        executed_cmds = format_executed_commands(attack_context)
                        if sensitive and executed_cmds:
                            executed_cmds = encryptor.encrypt(executed_cmds)
                        prompt = PROMPT_ATTACK_CONTINUE.format(
                            reason="completed its initial objectives",
                            executed_commands=executed_cmds,
                            iterations=iteration + 1,
                            successful_count=len(attack_context["successful_attacks"]),
                            vuln_count=len(attack_context["validated_vulns"]),
                            user_query=user_query,
                            targets=targets_str,
                            user_instructions=custom_prompt_suffix
                        )
                        yield Info(message=f"Continuing attack with new query: {user_query}")
                        continue

                    elif action_type == "stop":
                        reason = terminal_action.get("reason", "No reason provided")
                        yield AI(
                            content=reason,
                            ai_type='stopped',
                            mode='attack',
                            extra_data={
                                "iterations": iteration + 1,
                                "successful_attacks": len(attack_context["successful_attacks"]),
                                "validated_vulns": len(attack_context["validated_vulns"]),
                            },
                        )

                        user_query = prompt_user_for_continuation()
                        if user_query is None:
                            yield Info(message="User chose to stop. Ending attack loop.")
                            break

                        executed_cmds = format_executed_commands(attack_context)
                        if sensitive and executed_cmds:
                            executed_cmds = encryptor.encrypt(executed_cmds)
                        prompt = PROMPT_ATTACK_CONTINUE.format(
                            reason=f"stopped ({reason})",
                            executed_commands=executed_cmds,
                            iterations=iteration + 1,
                            successful_count=len(attack_context["successful_attacks"]),
                            vuln_count=len(attack_context["validated_vulns"]),
                            user_query=user_query,
                            targets=targets_str,
                            user_instructions=custom_prompt_suffix
                        )
                        yield Info(message=f"Continuing attack with new query: {user_query}")
                        continue

                # Process executable actions and collect batch results
                if len(executable_actions) > 1:
                    yield Info(message=f"Processing batch of {len(executable_actions)} actions...")

                batch_results = []  # Collect results for batch prompt
                skip_remaining = False

                for action_idx, action in enumerate(executable_actions):
                    if skip_remaining:
                        break

                    action_type = action.get("action", "")
                    action_num = action_idx + 1

                    if action_type == "execute":
                        exec_type = action.get("type", "shell")

                        # Handle secator runners (task, workflow, scan)
                        if exec_type in ("task", "workflow", "scan"):
                            if disable_secator:
                                yield Warning(
                                    message=f"[{action_num}/{len(executable_actions)}] Secator runners disabled. Rejecting {exec_type} '{action.get('name', '')}'."
                                )
                                batch_results.append({
                                    "action": f"{exec_type} '{action.get('name', '')}'",
                                    "status": "rejected",
                                    "output": "Secator runners are disabled. Use shell commands instead."
                                })
                                continue

                            name = action.get("name", "")
                            action_targets = action.get("targets", []) or targets
                            opts = action.get("opts", {})

                            valid_opts, invalid_opts, valid_opt_names = (
                                self._validate_runner_opts(exec_type, name, opts)
                            )

                            if invalid_opts:
                                yield Warning(
                                    message=f"[{action_num}/{len(executable_actions)}] Invalid options for {exec_type} '{name}': {invalid_opts}"
                                )
                                batch_results.append({
                                    "action": f"{exec_type} '{name}'",
                                    "status": "error",
                                    "output": f"Invalid options: {invalid_opts}. Valid options: {valid_opt_names}"
                                })
                                continue

                            cli_opts = " ".join(
                                f"--{k.replace('_', '-')} {v}"
                                if v is not True
                                else f"--{k.replace('_', '-')}"
                                for k, v in valid_opts.items()
                            )
                            cli_cmd = f"secator {exec_type[0]} {name} {','.join(action_targets)}"
                            if cli_opts:
                                cli_cmd += f" {cli_opts}"

                            auto_yes = self.run_opts.get("yes", False)
                            in_ci = _is_ci()
                            action_for_safety = {
                                "command": cli_cmd,
                                "destructive": action.get("destructive", False),
                                "aggressive": action.get("aggressive", False),
                                "reasoning": action.get("reasoning", ""),
                            }
                            should_run, modified_cmd = check_action_safety(
                                action_for_safety, auto_yes=auto_yes, in_ci=in_ci
                            )

                            if not should_run:
                                yield Info(message=f"[{action_num}/{len(executable_actions)}] Skipped: {cli_cmd}")
                                batch_results.append({
                                    "action": cli_cmd,
                                    "status": "skipped",
                                    "output": "User declined to run this command."
                                })
                                continue

                            if modified_cmd != cli_cmd:
                                cli_cmd = modified_cmd
                                yield Info(message=f"Command modified to: {cli_cmd}")

                            reasoning = action.get("reasoning", "")
                            yield AI(
                                content=cli_cmd,
                                ai_type=exec_type,
                                mode='attack',
                                extra_data={
                                    "reasoning": reasoning,
                                    "targets": action_targets,
                                    "opts": valid_opts,
                                    "batch_action": f"{action_num}/{len(executable_actions)}",
                                },
                            )

                            if dry_run:
                                result_output = f"[DRY RUN] {exec_type.capitalize()} '{name}' not executed"
                                runner_results = []
                                errors = []
                            else:
                                runner_results = []
                                vulnerabilities = []
                                errors = []
                                for result in self._execute_secator_runner(
                                    exec_type, name, action_targets, valid_opts
                                ):
                                    runner_results.append(result)
                                    if isinstance(result, Vulnerability):
                                        vulnerabilities.append(result)
                                    elif isinstance(result, Error):
                                        errors.append(result.message)
                                    else:
                                        self.add_result(result, print=False)

                                result_output = format_results_for_llm(runner_results)

                                # Include errors in output so AI can learn from them
                                if errors:
                                    error_text = "\n".join(f"ERROR: {e}" for e in errors)
                                    result_output = f"{error_text}\n\n{result_output}" if result_output else error_text

                                # Yield vulnerabilities as-is (AI should triage and validate if exploitable)
                                if vulnerabilities:
                                    yield Info(message=f"Found {len(vulnerabilities)} potential vulnerabilities - check for false positives, prioritize exploitable ones")
                                    for vuln in vulnerabilities:
                                        self.add_result(vuln, print=True)
                                        yield vuln

                            if verbose:
                                yield Info(message=f"[OUTPUT] {_truncate(result_output)}")

                            # Determine status based on errors
                            action_status = "error" if errors else "success"
                            attack_context["successful_attacks"].append({
                                "type": exec_type,
                                "name": name,
                                "targets": action_targets,
                                "result_count": len(runner_results),
                                "output": result_output[:2000],
                                "errors": errors,
                            })

                            batch_results.append({
                                "action": f"{exec_type.capitalize()} '{name}' on {action_targets}",
                                "status": action_status,
                                "output": result_output[:2000],
                                "result_count": len(runner_results),
                                "errors": errors,
                            })

                        elif exec_type == "shell":
                            command = action.get("command", "")
                            target = action.get("target", "")

                            auto_yes = self.run_opts.get("yes", False)
                            in_ci = _is_ci()
                            action_for_safety = {
                                "command": command,
                                "destructive": action.get("destructive", False),
                                "aggressive": action.get("aggressive", False),
                                "reasoning": action.get("reasoning", ""),
                            }
                            should_run, modified_cmd = check_action_safety(
                                action_for_safety, auto_yes=auto_yes, in_ci=in_ci
                            )

                            if not should_run:
                                yield Info(message=f"[{action_num}/{len(executable_actions)}] Skipped: {command}")
                                batch_results.append({
                                    "action": command,
                                    "status": "skipped",
                                    "output": "User declined to run this command."
                                })
                                continue

                            if modified_cmd != command:
                                command = modified_cmd
                                yield Info(message=f"Command modified to: {command}")

                            reasoning = action.get("reasoning", "")

                            # Display reasoning like secator workflow task descriptions
                            console.print("")
                            if reasoning:
                                console.print(f"🔧 [bold gold3]{reasoning} ...[/]")

                            # Display shell command like secator tasks (⚡ prefix)
                            console.print(f"⚡ [bold green]{command}[/]")

                            # Save AI record for shell command (without printing)
                            shell_ai = AI(
                                content=command,
                                ai_type='shell',
                                mode='attack',
                                extra_data={
                                    "reasoning": reasoning,
                                    "target": target,
                                    "batch_action": f"{action_num}/{len(executable_actions)}",
                                },
                            )
                            self.add_result(shell_ai, print=False)

                            if dry_run:
                                result_output = "[DRY RUN] Command not executed"
                            else:
                                result_output = self._execute_command(command)

                            # Show output inline (truncated to 1000 chars)
                            truncated_output = result_output[:1000] + ("..." if len(result_output) > 1000 else "")
                            console.print(truncated_output)

                            # Save AI record for shell output (without printing)
                            output_ai = AI(
                                content=truncated_output,
                                ai_type='shell_output',
                                mode='attack',
                            )
                            self.add_result(output_ai, print=False)

                            attack_context["successful_attacks"].append({
                                "type": "shell",
                                "command": command,
                                "target": target,
                                "output": result_output[:2000],
                            })

                            batch_results.append({
                                "action": f"Shell: {command}",
                                "status": "success",
                                "output": result_output[:2000],
                            })

                        else:
                            yield Warning(message=f"[{action_num}/{len(executable_actions)}] Unknown execute type: {exec_type}")
                            batch_results.append({
                                "action": f"Unknown type: {exec_type}",
                                "status": "error",
                                "output": f"Unknown execute type: {exec_type}"
                            })

                    elif action_type == "validate":
                        vuln_name = action.get("vulnerability", "Unknown")
                        target = action.get("target", "")
                        proof = action.get("proof", "")
                        severity = action.get("severity", "medium")
                        steps = action.get("reproduction_steps", [])

                        attack_context["validated_vulns"].append({
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
                                "model": model,
                            },
                        )

                        batch_results.append({
                            "action": f"Validate: {vuln_name}",
                            "status": "validated",
                            "output": f"Vulnerability '{vuln_name}' validated at {target} (severity: {severity})"
                        })

                    elif action_type == "report":
                        yield AI(
                            content=action.get("content", ""),
                            ai_type='report',
                            mode='attack',
                            extra_data=attack_context,
                        )
                        batch_results.append({
                            "action": "Report",
                            "status": "generated",
                            "output": action.get("content", "")[:500]
                        })

                    else:
                        yield Warning(message=f"[{action_num}/{len(executable_actions)}] Unknown action type: {action_type}")
                        batch_results.append({
                            "action": f"Unknown: {action_type}",
                            "status": "error",
                            "output": f"Unknown action type: {action_type}"
                        })

                # Build batch results prompt for next iteration
                if batch_results:
                    # Format batch results for LLM
                    batch_results_text = ""
                    for idx, result in enumerate(batch_results, 1):
                        batch_results_text += f"\n### Action {idx}: {result['action']}\n"
                        batch_results_text += f"**Status:** {result['status']}\n"
                        if result.get('errors'):
                            batch_results_text += "**Errors (fix these in next attempt):**\n"
                            for err in result['errors']:
                                batch_results_text += f"  - {err}\n"
                        if result.get('result_count'):
                            batch_results_text += f"**Results:** {result['result_count']} items\n"
                        batch_results_text += f"**Output:**\n```\n{result['output'][:1500]}\n```\n"

                    executed_cmds = format_executed_commands(attack_context)
                    if sensitive:
                        batch_results_text = encryptor.encrypt(batch_results_text)
                        if executed_cmds:
                            executed_cmds = encryptor.encrypt(executed_cmds)

                    prompt = PROMPT_ATTACK_BATCH_RESULTS.format(
                        action_count=len(batch_results),
                        batch_results=batch_results_text,
                        executed_commands=executed_cmds,
                        user_instructions=custom_prompt_suffix
                    )
                else:
                    # No executable actions and no terminal - shouldn't happen but handle gracefully
                    executed_cmds = format_executed_commands(attack_context)
                    if sensitive and executed_cmds:
                        executed_cmds = encryptor.encrypt(executed_cmds)
                    prompt = PROMPT_ATTACK_ERROR_UNKNOWN_ACTION.format(
                        action_type="none",
                        targets=targets_str,
                        executed_commands=executed_cmds,
                        user_instructions=custom_prompt_suffix
                    )

            except Exception as e:
                yield Error(
                    message=f"Attack iteration {iteration + 1} failed: {str(e)}"
                )
                attack_context["failed_attacks"].append({
                    "type": "error",
                    "name": "exception",
                    "error": str(e),
                    "targets": [],
                })
                # Build error prompt with executed commands
                executed_cmds = format_executed_commands(attack_context)
                if sensitive and executed_cmds:
                    executed_cmds = encryptor.encrypt(executed_cmds)
                prompt = PROMPT_ATTACK_ERROR_EXCEPTION.format(
                    error=str(e),
                    targets=targets_str,
                    executed_commands=executed_cmds,
                    user_instructions=custom_prompt_suffix
                )

        # Final summary if we hit max iterations
        if attack_context["iteration"] >= max_iterations:
            yield Warning(message=f"Max iterations ({max_iterations}) reached")
            # Generate comprehensive attack summary using LLM
            yield Info(message="Generating comprehensive attack summary...")
            full_summary = generate_attack_summary_with_llm(
                attack_context,
                model=model,
                api_base=api_base,
                temperature=temperature,
            )
            yield AI(
                content=full_summary,
                ai_type='attack_summary',
                mode='attack',
                model=model,
            )

    def _extract_commands(self, text: str) -> List[str]:
        """Extract secator commands from LLM response."""
        commands = []
        # Match secator commands in code blocks or inline
        patterns = [
            r"```[^\n]*\n(secator\s+[xwst]\s+[^\n]+)",
            r"`(secator\s+[xwst]\s+[^`]+)`",
            r"^(secator\s+[xwst]\s+\S+.*?)$",
        ]
        for pattern in patterns:
            matches = re.findall(pattern, text, re.MULTILINE)
            for match in matches:
                cmd = match.strip().strip("`")
                # Clean up the command
                cmd = re.sub(r"\s+", " ", cmd)
                if cmd and cmd not in commands:
                    commands.append(cmd)
        return commands

    def _parse_attack_actions(self, response: str) -> List[Dict]:
        """Parse JSON action(s) from LLM response. Returns list of actions."""
        def _normalize_to_list(parsed):
            """Convert parsed JSON to list of actions."""
            if isinstance(parsed, list):
                return [a for a in parsed if isinstance(a, dict) and "action" in a]
            elif isinstance(parsed, dict) and "action" in parsed:
                return [parsed]
            return []

        # Try direct parse (array or object)
        try:
            parsed = json.loads(response)
            actions = _normalize_to_list(parsed)
            if actions:
                return actions
        except json.JSONDecodeError:
            pass

        # Try to find JSON array in code blocks
        json_match = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", response, re.DOTALL)
        if json_match:
            try:
                parsed = json.loads(json_match.group(1))
                actions = _normalize_to_list(parsed)
                if actions:
                    return actions
            except json.JSONDecodeError:
                pass

        # Try to find JSON object in code blocks
        json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", response, re.DOTALL)
        if json_match:
            try:
                parsed = json.loads(json_match.group(1))
                actions = _normalize_to_list(parsed)
                if actions:
                    return actions
            except json.JSONDecodeError:
                pass

        # Try to find raw JSON array
        json_match = re.search(r'\[\s*\{.*?"action".*?\}\s*\]', response, re.DOTALL)
        if json_match:
            try:
                parsed = json.loads(json_match.group())
                actions = _normalize_to_list(parsed)
                if actions:
                    return actions
            except json.JSONDecodeError:
                pass

        # Try to find raw JSON object
        json_match = re.search(r'\{[^{}]*"action"[^{}]*\}', response, re.DOTALL)
        if json_match:
            try:
                parsed = json.loads(json_match.group())
                actions = _normalize_to_list(parsed)
                if actions:
                    return actions
            except json.JSONDecodeError:
                pass

        return []

    def _execute_command(self, command: str) -> str:
        """Execute a command and return output."""
        try:
            dangerous = self.run_opts.get("dangerous", False)

            # Security: only allow specific commands (unless dangerous mode)
            if not dangerous:
                # Allowed pentest tools by category:
                # - Secator: secator
                # - HTTP/Web: curl, wget, httpx, whatweb, wafw00f
                # - Crawling: katana, gospider, hakrawler
                # - Fuzzing: ffuf, feroxbuster, gobuster, dirsearch, wfuzz
                # - Port scanning: nmap, masscan, rustscan
                # - DNS: dig, host, nslookup, dnsx, subfinder, amass
                # - SQLi: sqlmap, ghauri
                # - XSS: dalfox, xsstrike
                # - LFI/RCE: commix, lfisuite
                # - Credentials: hydra, medusa, crackmapexec, netexec
                # - Nuclei/Templates: nuclei
                # - SSL/TLS: sslscan, testssl, sslyze
                # - CMS: wpscan, droopescan, joomscan
                # - Git: git, gitleaks, trufflehog
                # - Misc: jq, grep, awk, sed, cat, head, tail, echo, whoami, id, uname
                allowed_prefixes = [
                    # Secator
                    "secator ",
                    # HTTP/Web
                    "curl ", "wget ", "httpx ", "whatweb ", "wafw00f ",
                    # Crawling
                    "katana ", "gospider ", "hakrawler ",
                    # Fuzzing
                    "ffuf ", "feroxbuster ", "gobuster ", "dirsearch ", "wfuzz ",
                    # Port scanning
                    "nmap ", "masscan ", "rustscan ",
                    # DNS
                    "dig ", "host ", "nslookup ", "dnsx ", "subfinder ", "amass ",
                    # SQLi
                    "sqlmap ", "ghauri ",
                    # XSS
                    "dalfox ", "xsstrike ",
                    # LFI/RCE
                    "commix ",
                    # Credentials
                    "hydra ", "medusa ", "crackmapexec ", "netexec ", "cme ",
                    # Nuclei
                    "nuclei ",
                    # SSL/TLS
                    "sslscan ", "testssl ", "sslyze ",
                    # CMS
                    "wpscan ", "droopescan ", "joomscan ",
                    # Git
                    "git ", "gitleaks ", "trufflehog ",
                    # Misc utilities
                    "jq ", "grep ", "awk ", "sed ", "cat ", "head ", "tail ",
                    "echo ", "whoami ", "id ", "uname ", "ping ", "traceroute ",
                ]
                if not any(command.startswith(p) for p in allowed_prefixes):
                    allowed_tools = ", ".join(sorted(set(p.strip() for p in allowed_prefixes)))
                    return f"Command not allowed: {command}.\nAllowed tools: {allowed_tools}\nUse --dangerous flag to allow any command."

            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=120,
            )
            output = result.stdout + result.stderr

            # Normalize whitespace: collapse 3+ consecutive newlines to 2
            output = re.sub(r'\n{3,}', '\n\n', output)
            output = output.strip()

            # If secator command failed, append help output
            if result.returncode != 0 and command.startswith("secator "):
                help_output = self._get_secator_help(command)
                if help_output:
                    output += f"\n\n--- COMMAND HELP ---\n{help_output}"

            return output[:10000] if output else "No output"
        except subprocess.TimeoutExpired:
            return "Command timed out after 120 seconds"
        except Exception as e:
            return f"Execution error: {str(e)}"

    def _get_secator_help(self, command: str) -> Optional[str]:
        """Get help output for a failed secator command."""
        # Parse the secator command to extract task name
        # Format: secator x <task> ... or secator w <workflow> ...
        match = re.match(r"secator\s+([xwst])\s+(\S+)", command)
        if not match:
            return None

        runner_type = match.group(1)
        name = match.group(2)

        try:
            help_result = subprocess.run(
                f"secator {runner_type} {name} -h",
                shell=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            return help_result.stdout[:5000] if help_result.stdout else None
        except Exception:
            return None

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

            # Add common runner options that are always valid
            common_opts = ["profiles"]
            valid_opt_names.extend(common_opts)

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
        from secator.runners import Scan, Task, Workflow
        from secator.template import TemplateLoader

        # Set minimal options for running embedded
        run_opts = {
            "print_item": True,
            "print_line": False,
            "print_cmd": True,
            "print_progress": True,
            "print_start": True,
            "print_end": True,
            "print_target": False,
            "sync": self.sync,
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

            yield Info(
                message=f"{runner_type.capitalize()} '{name}' completed with {result_count} results"
            )

        except Exception as e:
            yield Error(message=f"Failed to execute {runner_type} '{name}': {str(e)}")
