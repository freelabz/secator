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
from secator.output_types import Ai, Error, Info, Tag, Vulnerability, Warning, FINDING_TYPES
from secator.rich import console
from secator.runners import PythonRunner
from secator.tasks.ai_history import ChatHistory, create_llm_summarizer
from secator.tasks.ai_prompt_builder import PromptBuilder

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


def get_output_types_reference() -> str:
    """Get the available output types for query actions.

    Dynamically generates the list from FINDING_TYPES so new types
    are automatically included.

    Returns:
        Formatted output types reference string.
    """
    type_names = [c.get_name() for c in FINDING_TYPES]
    lines = ["Available _type values for queries:"]
    for name in sorted(type_names):
        if name == "ai":
            lines.append(f'- "{name}" - Previous AI conversations and analysis (use this to get context from earlier discussions)')
        else:
            lines.append(f'- "{name}"')
    lines.append("")
    lines.append('IMPORTANT: When querying AI conversation history, use "_type": "ai" (NOT "a_i" or "A_I").')
    lines.append("Example to get previous AI context:")
    lines.append('{{"action": "query", "query": {{"_type": "ai"}}, "result_key": "previous_context", "reasoning": "Get context from previous AI analysis"}}')
    return "\n".join(lines)


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
- NOISY TASKS: Some tasks make many HTTP requests (nuclei, dalfox, ffuf, feroxbuster, cariddi, katana, gospider, hakrawler, x8, and other crawlers/fuzzers). Use these ONLY if user asks for comprehensive/full recon, OR with very constrained arguments (e.g., a specific nuclei template, a short custom wordlist)
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
Your response must be EXACTLY:
1. Brief analysis (1-3 sentences MAX)
2. JSON array of actions

Example:
```
Found a login form. Testing for SQL injection.

[{{"action": "execute", "type": "shell", "command": "curl ...", "reasoning": "test SQLi"}}]
```

CRITICAL: The system executes your actions and returns results as JSON.
NEVER predict or invent command outputs. NEVER include "TOOL:", "Output:", or fake execution logs.
Your job: analyze results, decide next actions, output JSON. That's it.

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

### query
Query workspace for existing findings. Requires -ws flag.
{{
  "action": "query",
  "query": {{"_type": "vulnerability", "severity": {{"$in": ["critical", "high"]}}}},
  "result_key": "critical_vulns",
  "reasoning": "why you need this data"
}}

Query operators: $in, $regex, $contains, $gt, $gte, $lt, $lte, $ne

{output_types_reference}

### output_type
Convert findings to structured Secator output types.
{{
  "action": "output_type",
  "output_type": "vulnerability|port|url|subdomain|ip|exploit|tag",
  "fields": {{
    "name": "required for most types",
    "severity": "critical|high|medium|low|info",
    "matched_at": "where it was found"
  }},
  "reasoning": "why creating this output"
}}

### prompt
Ask user for direction (auto-selects default in CI/auto mode).
{{
  "action": "prompt",
  "question": "What should I do?",
  "options": ["Option A", "Option B", "Option C"],
  "default": "Option A",
  "reasoning": "why user input needed"
}}

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
- NOISY TOOLS: Some tools make many HTTP requests (nuclei, dalfox, ffuf, feroxbuster, gobuster, nikto, wfuzz, and other crawlers/fuzzers). Use these ONLY if user asks for comprehensive/full recon, OR with very constrained arguments (e.g., a specific template, a short custom wordlist)
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
Your response must be EXACTLY:
1. Brief analysis (1-3 sentences MAX)
2. JSON array of actions

Example:
```
Found a login form. Testing for SQL injection.

[{{"action": "execute", "type": "shell", "command": "curl ...", "reasoning": "test SQLi"}}]
```

CRITICAL: The system executes your actions and returns results as JSON.
NEVER predict or invent command outputs. NEVER include "TOOL:", "Output:", or fake execution logs.
Your job: analyze results, decide next actions, output JSON. That's it.

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
2. Extract any targets mentioned in the prompt (if no targets provided via -t flag)
3. Whether workspace data is needed (e.g., if user asks about previous results, findings, or wants to analyze workspace data)
4. What workspace queries to run to fetch relevant data (only if use_workspace is true)

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
    "targets": ["extracted.target.com", "192.168.1.1"],
    "use_workspace": true|false,
    "queries": [
        {{"_type": "vulnerability", "severity": {{"$in": ["critical", "high"]}}}},
        {{"_type": "url", "url": {{"$contains": "login"}}}}
    ],
    "reasoning": "Brief explanation of why this mode and these queries"
}}

## Target Extraction

Extract targets from the prompt if no explicit targets provided. Look for:
- Domain names: example.com, sub.domain.org
- URLs: http://example.com, https://api.example.com/path
- IP addresses: 192.168.1.1, 10.0.0.0/24
- Hostnames: my-server.local

Examples:
- "Attack jahmyst.synology.me" -> targets: ["jahmyst.synology.me"]
- "Scan http://test.com and 192.168.1.1" -> targets: ["http://test.com", "192.168.1.1"]
- "What vulnerabilities did we find?" -> targets: [] (no targets, workspace query)

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
                wordlists_reference=get_wordlists_reference(),
                output_types_reference=get_output_types_reference()
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

        # Then replace placeholders without brackets (e.g., HOST:a07963bdcb1f)
        # LLM sometimes strips the square brackets from placeholders
        for placeholder, original in self.pii_map.items():
            # Convert [TYPE:hash] to TYPE:hash
            no_brackets = placeholder[1:-1]  # Remove [ and ]
            result = result.replace(no_brackets, original)

        # Finally replace bare hashes (e.g., a07963bdcb1f) that LLM might extract
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
    workspace_id: Optional[str] = None
    workspace_name: Optional[str] = None
    drivers: List[str] = field(default_factory=list)


# =============================================================================
# ACTION HANDLER REGISTRY
# =============================================================================

ACTION_HANDLERS = {
    "execute": "_handle_execute",
    "validate": "_handle_validate",
    "complete": "_handle_complete",
    "stop": "_handle_stop",
    "report": "_handle_report",
    # Phase 2:
    "query": "_handle_query",
    "output_type": "_handle_output_type",
    "prompt": "_handle_prompt",
}

# =============================================================================
# OUTPUT TYPE MAPPING
# =============================================================================

OUTPUT_TYPE_MAP = {
    "vulnerability": "Vulnerability",
    "exploit": "Exploit",
    "port": "Port",
    "url": "Url",
    "subdomain": "Subdomain",
    "ip": "Ip",
    "domain": "Domain",
    "tag": "Tag",
    "record": "Record",
    "certificate": "Certificate",
    "user_account": "UserAccount",
}

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
        "allowed_actions": ["execute", "validate", "complete", "stop", "report", "query", "output_type", "prompt"],
    },
}


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


def _strip_hallucinations(text: str) -> str:
    """Strip hallucinated content after JSON array.

    LLMs sometimes produce: "analysis + JSON + hallucinated TOOL:/Status:/Output: sections"
    This keeps only the valid part: analysis + JSON array.
    """
    if not text:
        return text

    # Find the JSON array (starts with [ and contains "action")
    # and return everything up to and including the closing ]
    bracket_start = -1
    for i, char in enumerate(text):
        if char == '[':
            lookahead = text[i:i + 100]
            if '"action"' in lookahead:
                bracket_start = i
                break

    if bracket_start == -1:
        return text  # No JSON array found, return as-is

    # Find matching closing bracket
    bracket_count = 0
    bracket_end = -1
    for i in range(bracket_start, len(text)):
        if text[i] == '[':
            bracket_count += 1
        elif text[i] == ']':
            bracket_count -= 1
            if bracket_count == 0:
                bracket_end = i
                break

    if bracket_end == -1:
        return text  # Malformed JSON, return as-is

    # Return only: text before JSON + JSON array (strip everything after)
    return text[:bracket_end + 1].strip()


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
    api_base: str = None,
    encryptor: 'SensitiveDataEncryptor' = None,
) -> Optional[Dict[str, Any]]:
    """Phase 1: Analyze user intent and generate queries.

    Args:
        prompt: User prompt
        targets: List of targets
        model: LLM model to use
        verbose: Enable verbose output
        api_base: Optional API base URL
        encryptor: Optional encryptor for sensitive data

    Returns:
        Dict with intent info and '_usage' key containing token/cost info
    """
    # Encrypt sensitive data if encryptor provided
    if encryptor:
        prompt = encryptor.encrypt(prompt)
        targets = [encryptor.encrypt(t) for t in targets]

    user_message = f"Prompt: {prompt}"
    if targets:
        user_message += f"\nTargets: {', '.join(targets)}"

    system_prompt = PROMPT_INTENT_ANALYSIS.format(
        output_types_schema=get_output_types_schema()
    )

    llm_result = get_llm_response(
        prompt=user_message,
        model=model,
        system_prompt=system_prompt,
        temperature=0.3,
        verbose=verbose,
        api_base=api_base,
        return_usage=True,
    )

    if not llm_result:
        return None

    response = llm_result["content"] if isinstance(llm_result, dict) else llm_result
    usage_info = llm_result.get("usage") if isinstance(llm_result, dict) else None

    result = parse_intent_response(response)
    if result and usage_info:
        result["_usage"] = usage_info
    return result


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
    return_usage: bool = False,
) -> Optional[str]:
    """Get response from LLM using LiteLLM with exponential backoff for rate limits.

    Args:
        return_usage: If True, return dict with 'content' and 'usage' keys instead of just content
    """
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

                # Extract token usage and cost
                usage_info = None
                if hasattr(response, 'usage') and response.usage:
                    usage = response.usage
                    prompt_tokens = getattr(usage, 'prompt_tokens', 0)
                    completion_tokens = getattr(usage, 'completion_tokens', 0)
                    total_tokens = getattr(usage, 'total_tokens', 0)

                    # Try to get cost estimate
                    try:
                        cost = litellm.completion_cost(completion_response=response)
                    except Exception:
                        cost = None

                    usage_info = {
                        "prompt_tokens": prompt_tokens,
                        "completion_tokens": completion_tokens,
                        "total_tokens": total_tokens,
                        "cost": cost,
                    }

                    # Only print to console if not returning usage
                    if not return_usage:
                        cost_str = f", cost: ${cost:.4f}" if cost else ""
                        console.print(
                            f"[dim]📊 Tokens: {prompt_tokens} prompt + {completion_tokens} completion = {total_tokens} total{cost_str}[/]"
                        )

                content = response.choices[0].message.content
                if return_usage:
                    return {"content": content, "usage": usage_info}
                return content
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
        "output": "",
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

    output_types = [Vulnerability, Tag, Info, Warning, Error, Ai]
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
        "prompt_iterations": {
            "type": int,
            "default": None,
            "help": "Prompt user for direction every N iterations (default: min(max_iterations/2, 5))",
        },
        "summary_model": {
            "type": str,
            "default": "claude-haiku-4-5",
            "help": "Model for summarizing chat history (default: claude-haiku-4-5)",
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

        # Load custom sensitive patterns if provided (needed early for intent analysis)
        custom_patterns = []
        if sensitive_list:
            custom_patterns = load_sensitive_patterns(sensitive_list)
            if custom_patterns:
                yield Info(
                    message=f"Loaded {len(custom_patterns)} custom sensitive patterns"
                )

        # Initialize sensitive data encryptor early (for intent analysis encryption)
        encryptor = SensitiveDataEncryptor(custom_patterns=custom_patterns)

        # Phase 1: Intent Analysis
        queries = [{}]
        use_workspace = False  # Default to NOT using workspace unless explicitly requested
        intent_usage = None
        if prompt and not mode_override:
            intent = analyze_intent(
                prompt=prompt,
                targets=targets,
                model=intent_model,
                verbose=verbose,
                api_base=api_base,
                encryptor=encryptor if sensitive else None,
            )
            if intent:
                mode = intent.get("mode", "summarize")
                use_workspace = intent.get("use_workspace", False)
                queries = intent.get("queries", [{}])
                intent_usage = intent.get("_usage")
                # Use extracted targets if none provided via -t flag
                extracted_targets = intent.get("targets", [])
                if not targets and extracted_targets:
                    targets = extracted_targets
                    yield Info(message=f"Extracted targets from prompt: {', '.join(targets)}")
                yield Info(message=f"Mode: {mode}, Use workspace: {use_workspace}, Queries: {len(queries)}")
            else:
                yield Warning(message="Could not analyze intent, defaulting to summarize mode")
                mode = "summarize"
        else:
            mode = mode_override or "summarize"

        # Show the user's prompt with usage info (after intent analysis)
        if prompt:
            if prompt_from_file:
                yield Info(message=f"Loaded prompt from file: {prompt_input}")
            # Build extra_data with usage info if available
            prompt_extra = {}
            if intent_usage:
                prompt_extra["tokens"] = intent_usage.get("total_tokens")
                prompt_extra["cost"] = intent_usage.get("cost")
            yield Ai(content=prompt, ai_type='prompt', extra_data=prompt_extra)

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
                # Decrypt query values if sensitive mode (queries from intent analysis may have encrypted values)
                if sensitive:
                    query = self._decrypt_query(query, encryptor)
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
                yield Ai(content=f"{prompt}\n[CUSTOM PROMPT]{formatted_custom}", ai_type='prompt')
            else:
                yield Ai(content=prompt, ai_type='prompt')

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
            yield Ai(
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
                yield Ai(content=f"{prompt}\n[CUSTOM PROMPT]{formatted_custom}", ai_type='prompt')
            else:
                yield Ai(content=prompt, ai_type='prompt')

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
            yield Ai(
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

        # Calculate prompt_iterations default
        prompt_iterations = self.run_opts.get("prompt_iterations")
        if prompt_iterations is None:
            prompt_iterations = min(max_iterations // 2, 5)
        else:
            prompt_iterations = int(prompt_iterations)

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

        # Build action context for dispatch system
        ctx = self._build_action_context(
            targets=targets,
            model=model,
            encryptor=encryptor,
            api_base=api_base,
            attack_context=attack_context,
            custom_prompt_suffix=custom_prompt_suffix,
        )

        # Initialize chat history for this attack session
        chat_history = ChatHistory()

        # Initialize prompt builder
        prompt_builder = PromptBuilder(disable_secator=disable_secator)

        # Get summary model (default to claude-haiku-4-5)
        summary_model = self.run_opts.get("summary_model", "claude-haiku-4-5")

        # Build initial prompt using PromptBuilder
        # Include context in instructions if workspace data is available
        if use_workspace and results:
            combined_instructions = f"## Current Findings\n{context_text}\n\n{custom_prompt}" if custom_prompt else f"## Current Findings\n{context_text}"
        else:
            combined_instructions = custom_prompt if custom_prompt else ""

        full_prompt = prompt_builder.build_full_prompt(
            targets=targets,
            instructions=combined_instructions,
            history=chat_history,
            iteration=1,
            max_iterations=max_iterations,
        )

        # Encrypt at the edge if sensitive mode
        if sensitive:
            full_prompt = prompt_builder.encrypt_prompt(full_prompt, encryptor)

        # Format for LLM (and debug version for verbose)
        prompt = prompt_builder.format_prompt_for_llm(full_prompt)
        debug_prompt = prompt_builder.format_iteration_for_debug(full_prompt)

        if disable_secator:
            yield Info(message="Secator runners disabled - using shell commands only")

        for iteration in range(max_iterations):
            attack_context["iteration"] = iteration + 1
            yield Info(message=f"Attack iteration {iteration + 1}/{max_iterations}")

            # Periodic checkpoint (skip first iteration, skip in CI/auto_yes)
            if iteration > 0 and prompt_iterations > 0 and iteration % prompt_iterations == 0:
                if not ctx.in_ci and not ctx.auto_yes:
                    yield from self._prompt_checkpoint(iteration + 1, max_iterations, ctx)

                    checkpoint_result = ctx.attack_context.get('_checkpoint_result', 'continue')

                    if checkpoint_result == 'stop':
                        yield Info(message="User requested stop at checkpoint")
                        break
                    elif checkpoint_result == 'change':
                        new_instructions = self._get_new_instructions(ctx)
                        if new_instructions:
                            custom_prompt_suffix = new_instructions
                            yield Info(message=f"New instructions: {new_instructions}")

                    # Summarize history at checkpoint
                    if len(chat_history.messages) > 4:
                        summarizer = create_llm_summarizer(
                            model=summary_model,
                            api_base=api_base,
                            temperature=0.3,
                        )
                        yield Info(message="Summarizing chat history...")
                        chat_history.summarize(summarizer=summarizer, keep_last=4)

            try:
                # Show debug prompt (history + query) in verbose mode
                if verbose:
                    yield Ai(content=debug_prompt, ai_type='prompt')

                llm_result = get_llm_response(
                    prompt=prompt,
                    model=model,
                    system_prompt=get_system_prompt("attack", disable_secator=disable_secator),
                    temperature=temperature,
                    api_base=api_base,
                    return_usage=True,
                )
                response = llm_result["content"] if isinstance(llm_result, dict) else llm_result
                usage_info = llm_result.get("usage") if isinstance(llm_result, dict) else None

                # Decrypt sensitive data
                if self.run_opts.get("sensitive", True):
                    response = encryptor.decrypt(response)

                # Add assistant response to history (strip hallucinated content)
                clean_response = _strip_hallucinations(response)
                chat_history.add_assistant(clean_response)

                # Parse actions from response (now returns list)
                actions = self._parse_attack_actions(response)

                # Show AI response with markdown rendering
                # In verbose mode show clean response (analysis + JSON), otherwise strip JSON
                if verbose:
                    response_display = clean_response
                else:
                    response_display = _strip_json_from_response(clean_response)

                # Build extra_data with iteration and usage info
                extra_data = {"iteration": iteration + 1, "max_iterations": max_iterations}
                if usage_info:
                    extra_data["tokens"] = usage_info.get("total_tokens")
                    extra_data["cost"] = usage_info.get("cost")

                if response_display:
                    yield Ai(
                        content=response_display,
                        ai_type='response',
                        mode='attack',
                        model=model,
                        extra_data=extra_data,
                    )

                if not actions:
                    yield Warning(message="Could not parse actions from LLM response")
                    # Resend previous context with the invalid response so LLM can fix it
                    executed_cmds = format_executed_commands(ctx.attack_context)
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

                # Process executable actions and collect batch results
                if len(executable_actions) > 1:
                    yield Info(message=f"Processing batch of {len(executable_actions)} actions...")

                batch_results = []  # Collect results for batch prompt

                for action_idx, action in enumerate(executable_actions):
                    action_num = action_idx + 1
                    total_actions = len(executable_actions)

                    # Inject action numbering for handlers
                    action["_action_num"] = action_num
                    action["_total_actions"] = total_actions

                    # Dispatch to handler
                    for result in self._dispatch_action(action, ctx):
                        yield result

                    # Collect batch result from handler
                    if "_result" in action:
                        batch_results.append(action["_result"])

                # Build batch results prompt for next iteration
                if batch_results:
                    # Format batch results for LLM
                    batch_results_text = self._format_batch_results(batch_results)

                    # Add tool results to history
                    chat_history.add_tool(batch_results_text)

                    # Build prompt for next iteration using PromptBuilder
                    prompt, debug_prompt = self._build_iteration_prompt(
                        prompt_builder=prompt_builder,
                        chat_history=chat_history,
                        targets=targets,
                        instructions=combined_instructions,
                        iteration=iteration + 1,
                        max_iterations=max_iterations,
                        encryptor=encryptor,
                        sensitive=sensitive,
                    )
                else:
                    # No executable actions and no terminal - shouldn't happen but handle gracefully
                    executed_cmds = format_executed_commands(ctx.attack_context)
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
                ctx.attack_context["failed_attacks"].append({
                    "type": "error",
                    "name": "exception",
                    "error": str(e),
                    "targets": [],
                })
                # Build error prompt with executed commands
                executed_cmds = format_executed_commands(ctx.attack_context)
                if sensitive and executed_cmds:
                    executed_cmds = encryptor.encrypt(executed_cmds)
                prompt = PROMPT_ATTACK_ERROR_EXCEPTION.format(
                    error=str(e),
                    targets=targets_str,
                    executed_commands=executed_cmds,
                    user_instructions=custom_prompt_suffix
                )

        # End-of-loop continuation
        should_generate_summary = True

        while not ctx.in_ci and not ctx.auto_yes:
            yield from self._prompt_continuation(ctx)

            continuation_result = ctx.attack_context.get('_continuation_result', 'stop')

            if continuation_result == 'stop':
                break
            elif continuation_result == 'continue':
                # Run another batch of iterations
                yield Info(message=f"Continuing for {prompt_iterations} more iterations...")
                for extra_iteration in range(prompt_iterations):
                    ctx.attack_context["iteration"] += 1
                    yield Info(message=f"Extra iteration {extra_iteration + 1}/{prompt_iterations}")

                    # Run one iteration of the attack loop
                    try:
                        response = get_llm_response(
                            prompt=prompt,
                            model=model,
                            system_prompt=get_system_prompt("attack", disable_secator=disable_secator),
                            temperature=temperature,
                            api_base=api_base,
                        )
                        if sensitive:
                            response = encryptor.decrypt(response)

                        actions = self._parse_attack_actions(response)
                        if actions:
                            for action in actions:
                                action_type = action.get("action", "")
                                if action_type in ("complete", "stop"):
                                    should_generate_summary = True
                                    break
                                for result in self._dispatch_action(action, ctx):
                                    yield result
                    except Exception as e:
                        yield Warning(message=f"Continuation iteration failed: {e}")

            elif continuation_result == 'change':
                new_instructions = self._get_new_instructions(ctx)
                if new_instructions:
                    custom_prompt_suffix = new_instructions
                    prompt = self._build_continuation_prompt(ctx, new_instructions, encryptor, sensitive)
                    yield Info(message=f"New instructions applied: {new_instructions}")
                    continue
            else:
                break

        # Generate final summary
        if should_generate_summary:
            yield Info(message="Generating comprehensive attack summary...")
            full_summary = generate_attack_summary_with_llm(
                ctx.attack_context,
                model=ctx.model,
                api_base=ctx.api_base,
                temperature=ctx.temperature,
            )
            yield Ai(
                content=full_summary,
                ai_type='attack_summary',
                mode='attack',
                model=ctx.model,
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

    def _handle_report(self, action: Dict, ctx: 'ActionContext') -> Generator:
        """Handle report action - yield AI report output.

        Args:
            action: Report action with content
            ctx: ActionContext with attack_context

        Yields:
            AI output type with report content
        """
        yield Ai(
            content=action.get("content", ""),
            ai_type='report',
            mode='attack',
            extra_data=ctx.attack_context,
        )

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
        yield Ai(
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

    def _handle_stop(self, action: Dict, ctx: 'ActionContext') -> Generator:
        """Handle stop action - display reason and prompt for continuation.

        Args:
            action: Stop action with reason
            ctx: ActionContext with full state

        Yields:
            AI output with stop reason
        """
        reason = action.get("reason", "No reason provided")
        yield Ai(
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

    def _handle_query(self, action: Dict, ctx: 'ActionContext') -> Generator:
        """Handle query action - fetch workspace results.

        Args:
            action: Query action with MongoDB-style query
            ctx: ActionContext with workspace info

        Yields:
            Info or Warning/Error outputs
        """
        query = action.get("query", {})
        result_key = action.get("result_key", "query_results")

        # Decrypt query values if sensitive mode (LLM sends encrypted placeholders)
        if ctx.sensitive and ctx.encryptor:
            query = self._decrypt_query(query, ctx.encryptor)

        # Display query as Ai item
        import json
        query_str = json.dumps(query, indent=2) if query else "{}"
        yield Ai(
            content=query_str,
            ai_type='query',
            mode='attack',
            extra_data={
                "reasoning": action.get("reasoning", ""),
                "result_key": result_key,
            }
        )

        # Check workspace context
        if not ctx.workspace_id:
            yield Warning(message="Query action requires workspace context (-ws flag)")
            return

        # Execute query
        try:
            from secator.query import QueryEngine
            engine = QueryEngine(ctx.workspace_id, {
                'workspace_name': ctx.workspace_name,
                'drivers': ctx.drivers,
            })
            results = engine.search(query, limit=100)

            # Format results for context
            formatted = self._format_query_results(results)
            ctx.attack_context[result_key] = formatted

            # Set _result for batch processing so results are sent back to LLM
            action["_result"] = {
                "action": "query",
                "status": "success",
                "result_count": len(results),
                "output": f"Query results stored in '{result_key}':\n{formatted}",
            }

            yield Info(message=f"Query returned {len(results)} results (stored in {result_key})")

        except Exception as e:
            action["_result"] = {
                "action": "query",
                "status": "failed",
                "errors": [str(e)],
                "output": f"Query failed: {e}",
            }
            yield Error(message=f"Query failed: {e}")

    def _format_query_results(self, results: List[Dict]) -> str:
        """Format query results as string for LLM context.

        Args:
            results: List of result dictionaries

        Returns:
            Formatted string representation
        """
        if not results:
            return "No results found."

        lines = [f"Found {len(results)} results:"]
        for i, r in enumerate(results[:20], 1):  # Limit to 20 for context
            rtype = r.get('_type', 'unknown')
            if rtype == 'vulnerability':
                lines.append(f"  {i}. [{r.get('severity', '?')}] {r.get('name', '?')} @ {r.get('matched_at', '?')}")
            elif rtype == 'port':
                lines.append(f"  {i}. {r.get('ip', '?')}:{r.get('port', '?')} ({r.get('service_name', '?')})")
            elif rtype == 'url':
                lines.append(f"  {i}. {r.get('url', '?')} [{r.get('status_code', '?')}]")
            else:
                lines.append(f"  {i}. [{rtype}] {str(r)[:80]}")

        if len(results) > 20:
            lines.append(f"  ... and {len(results) - 20} more")

        return "\n".join(lines)

    def _decrypt_query(self, query: Dict, encryptor: 'SensitiveDataEncryptor') -> Dict:
        """Recursively decrypt all string values in a query dict.

        Args:
            query: Query dict with potentially encrypted values
            encryptor: Encryptor to decrypt values

        Returns:
            Query dict with decrypted values
        """
        if isinstance(query, str):
            return encryptor.decrypt(query)
        elif isinstance(query, dict):
            return {k: self._decrypt_query(v, encryptor) for k, v in query.items()}
        elif isinstance(query, list):
            return [self._decrypt_query(item, encryptor) for item in query]
        else:
            return query

    def _handle_output_type(self, action: Dict, ctx: 'ActionContext') -> Generator:
        """Handle output_type action - convert output to structured type.

        Args:
            action: Action with output_type and fields
            ctx: ActionContext (unused but required for interface)

        Yields:
            OutputType instance or Warning/Error
        """
        output_type = action.get("output_type", "").lower()
        fields_data = action.get("fields", {})

        # Validate output type
        if output_type not in OUTPUT_TYPE_MAP:
            valid_types = list(OUTPUT_TYPE_MAP.keys())
            yield Warning(message=f"Unknown output_type: {output_type}. Valid: {valid_types}")
            return

        # Import and create instance
        try:
            class_name = OUTPUT_TYPE_MAP[output_type]

            # Import from secator.output_types
            from secator import output_types
            OutputClass = getattr(output_types, class_name)

            # Add source metadata
            fields_data['_source'] = 'ai'

            instance = OutputClass(**fields_data)
            yield instance

        except TypeError as e:
            yield Error(message=f"Invalid fields for {output_type}: {e}")
        except Exception as e:
            yield Error(message=f"Failed to create {output_type}: {e}")

    def _handle_prompt(self, action: Dict, ctx: 'ActionContext') -> Generator:
        """Handle prompt action - ask user for direction.

        Args:
            action: Prompt action with question and options
            ctx: ActionContext with mode flags

        Yields:
            AI prompt output and Info/Warning about selection
        """
        question = action.get("question", "")
        options = action.get("options", [])
        default = action.get("default", options[0] if options else "")

        # Display the question
        yield Ai(
            content=question,
            ai_type="prompt",
            mode="attack",
            extra_data={"options": options, "default": default},
        )

        # Check if interactive mode
        if ctx.in_ci or ctx.auto_yes:
            yield Info(message=f"Auto-selecting: {default} (non-interactive mode)")
            ctx.attack_context["user_response"] = default
            return

        # Interactive prompt
        try:
            from rich.prompt import Prompt

            # Build choices display
            choices_display = " / ".join(f"[{i+1}] {opt}" for i, opt in enumerate(options))

            response = Prompt.ask(
                f"[bold cyan]Choose[/] ({choices_display})",
                choices=[str(i+1) for i in range(len(options))] + options,
                default="1",
            )

            # Convert number to option if needed
            if response.isdigit() and 1 <= int(response) <= len(options):
                selected = options[int(response) - 1]
            else:
                selected = response

            ctx.attack_context["user_response"] = selected
            yield Info(message=f"User selected: {selected}")

        except Exception as e:
            yield Warning(message=f"Prompt failed: {e}, using default: {default}")
            ctx.attack_context["user_response"] = default

    def _prompt_checkpoint(self, iteration: int, max_iterations: int, ctx: 'ActionContext') -> Generator:
        """Prompt user at periodic checkpoint.

        Args:
            iteration: Current iteration number (1-indexed)
            max_iterations: Total max iterations
            ctx: ActionContext with mode flags

        Yields:
            AI and Info outputs from _handle_prompt
        """
        checkpoint_action = {
            "action": "prompt",
            "question": f"Checkpoint at iteration {iteration}/{max_iterations}. How should I proceed?",
            "options": [
                "Continue attacking",
                "Change direction",
                "Stop and summarize"
            ],
            "default": "Continue attacking",
        }

        yield from self._handle_prompt(checkpoint_action, ctx)

        # Parse response and store result
        result = self._parse_checkpoint_response(ctx)
        ctx.attack_context['_checkpoint_result'] = result

    def _parse_checkpoint_response(self, ctx: 'ActionContext') -> str:
        """Parse checkpoint response into action.

        Returns:
            'continue', 'stop', or 'change'
        """
        user_response = ctx.attack_context.get("user_response", "Continue attacking")

        if "Stop" in user_response:
            return "stop"
        elif "Change" in user_response:
            return "change"
        else:
            return "continue"

    def _prompt_continuation(self, ctx: 'ActionContext') -> Generator:
        """Prompt user for continuation after loop ends.

        Args:
            ctx: ActionContext with mode flags

        Yields:
            AI and Info outputs from _handle_prompt
        """
        continuation_action = {
            "action": "prompt",
            "question": "Attack loop completed. What would you like to do?",
            "options": [
                "Continue with more iterations",
                "Provide new instructions",
                "Stop and generate report"
            ],
            "default": "Stop and generate report",
        }

        yield from self._handle_prompt(continuation_action, ctx)

        # Parse response and store result
        result = self._parse_continuation_response(ctx)
        ctx.attack_context['_continuation_result'] = result

    def _parse_continuation_response(self, ctx: 'ActionContext') -> str:
        """Parse continuation response into action.

        Returns:
            'continue', 'stop', or 'change'
        """
        user_response = ctx.attack_context.get("user_response", "Stop")

        if "Stop" in user_response:
            return "stop"
        elif "Continue" in user_response:
            return "continue"
        else:
            return "change"

    def _get_new_instructions(self, ctx: 'ActionContext') -> str:
        """Get new instructions from user.

        Args:
            ctx: ActionContext with mode flags

        Returns:
            User's new instructions or empty string in CI mode
        """
        if ctx.in_ci or ctx.auto_yes:
            return ""

        try:
            from rich.prompt import Prompt
            return Prompt.ask("[bold cyan]New instructions[/]")
        except Exception:
            return ""

    def _build_continuation_prompt(
        self, ctx: 'ActionContext', new_instructions: str,
        encryptor: 'SensitiveDataEncryptor', sensitive: bool
    ) -> str:
        """Build prompt for continuation with new instructions.

        Args:
            ctx: ActionContext with attack context
            new_instructions: User's new instructions
            encryptor: Encryptor for sensitive data
            sensitive: Whether to encrypt

        Returns:
            Formatted prompt string
        """
        executed_cmds = format_executed_commands(ctx.attack_context)
        if sensitive and executed_cmds:
            executed_cmds = encryptor.encrypt(executed_cmds)

        targets_str = ", ".join(ctx.targets)
        if sensitive:
            targets_str = encryptor.encrypt(targets_str)

        return PROMPT_ATTACK_CONTINUE.format(
            reason="received new instructions from user",
            executed_commands=executed_cmds,
            iterations=ctx.attack_context.get("iteration", 0),
            successful_count=len(ctx.attack_context.get("successful_attacks", [])),
            vuln_count=len(ctx.attack_context.get("validated_vulns", [])),
            user_query=new_instructions,
            targets=targets_str,
            user_instructions=""
        )

    def _build_iteration_prompt(
        self,
        prompt_builder: 'PromptBuilder',
        chat_history: 'ChatHistory',
        targets: List[str],
        instructions: str,
        iteration: int,
        max_iterations: int,
        encryptor: 'SensitiveDataEncryptor',
        sensitive: bool,
    ) -> tuple:
        """Build prompt for an attack iteration.

        Args:
            prompt_builder: PromptBuilder instance
            chat_history: ChatHistory with conversation so far
            targets: List of targets
            instructions: User instructions
            iteration: Current iteration number
            max_iterations: Maximum iterations
            encryptor: Encryptor for sensitive data
            sensitive: Whether to encrypt

        Returns:
            Tuple of (formatted_prompt, debug_prompt) where debug_prompt
            contains only history + current query for verbose debugging
        """
        full_prompt = prompt_builder.build_full_prompt(
            targets=targets,
            instructions=instructions,
            history=chat_history,
            iteration=iteration,
            max_iterations=max_iterations,
        )

        if sensitive:
            full_prompt = prompt_builder.encrypt_prompt(full_prompt, encryptor)

        return (
            prompt_builder.format_prompt_for_llm(full_prompt),
            prompt_builder.format_iteration_for_debug(full_prompt),
        )

    def _prepare_runner(
        self,
        action: Dict,
        ctx: 'ActionContext',
        action_num: int,
        total_actions: int
    ) -> Dict:
        """Prepare runner execution - validate opts, build command, do safety check.

        Args:
            action: Execute action with type, name, targets, opts
            ctx: ActionContext with execution state
            action_num: Current action number in batch
            total_actions: Total actions in batch

        Returns:
            Dict with either:
            - Preview info (cli_cmd, reasoning, etc.) if ready to execute
            - Early return result with "_early_return": True if should skip/error
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
                "_early_return": True,
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
                "_early_return": True,
                "action": cli_cmd,
                "status": "skipped",
                "output": "User declined to run this command.",
                "info": f"[{action_num}/{total_actions}] Skipped: {cli_cmd}"
            }

        if modified_cmd != cli_cmd:
            cli_cmd = modified_cmd

        # Return preview info for Ai output before execution
        return {
            "cli_cmd": cli_cmd,
            "reasoning": action.get("reasoning", ""),
            "exec_type": exec_type,
            "name": name,
            "targets": action_targets,
            "opts": valid_opts,
            "batch_action": f"{action_num}/{total_actions}",
        }

    def _run_prepared_runner(self, preview: Dict, ctx: 'ActionContext') -> Dict:
        """Execute a prepared runner and return results.

        Args:
            preview: Preview info from _prepare_runner
            ctx: ActionContext with execution state

        Returns:
            Dict with action, status, output, result_count, errors for batch results
        """
        exec_type = preview["exec_type"]
        name = preview["name"]
        action_targets = preview["targets"]
        valid_opts = preview["opts"]

        result = {
            "action": f"{exec_type.capitalize()} '{name}' on {action_targets}",
            "cli_cmd": preview["cli_cmd"],
            "reasoning": preview["reasoning"],
            "exec_type": exec_type,
            "name": name,
            "targets": action_targets,
            "opts": valid_opts,
            "batch_action": preview["batch_action"],
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

            # Phase 1: Prepare (validate, build command, safety check)
            preview = self._prepare_runner(action, ctx, action_num, total_actions)

            # Handle early returns (validation error or user declined)
            if preview.get("_early_return"):
                if preview.get("warning"):
                    yield Warning(message=preview["warning"])
                if preview.get("info"):
                    yield Info(message=preview["info"])
                action["_result"] = preview
                return

            # Phase 2: Display command BEFORE execution
            yield Ai(
                content=preview.get("cli_cmd", ""),
                ai_type=exec_type,
                mode='attack',
                extra_data={
                    "reasoning": preview.get("reasoning", ""),
                    "targets": preview.get("targets", []),
                    "opts": preview.get("opts", {}),
                    "batch_action": preview.get("batch_action", ""),
                },
            )

            # Phase 3: Execute
            result = self._run_prepared_runner(preview, ctx)

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
                shell_ai = Ai(
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
                console.print(f'[dim]{truncated}[/]', highlight=False)

                output_ai = Ai(
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
        # Get workspace context from self.context
        workspace_id = self.context.get("workspace_id") if self.context else None
        workspace_name = self.context.get("workspace_name") if self.context else None
        drivers = self.context.get("drivers", []) if self.context else []

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
            workspace_id=workspace_id,
            workspace_name=workspace_name,
            drivers=drivers,
        )

    def _format_batch_results(self, batch_results: list) -> str:
        """Format batch results for LLM prompt as JSON.

        Args:
            batch_results: List of result dicts from action handlers

        Returns:
            JSON string for LLM
        """
        import json
        results = []
        for result in batch_results:
            r = {
                "action": result.get("action", "unknown"),
                "status": result.get("status", "unknown"),
            }
            if result.get("errors"):
                r["errors"] = result["errors"]
            if result.get("result_count"):
                r["result_count"] = result["result_count"]
            # Truncate output to save tokens
            output = result.get("output", "")
            if output:
                r["output"] = output[:1500]
            results.append(r)
        return json.dumps(results, indent=2)

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
            "print_start": False,
            "print_end": False,
            "print_target": False,
            "sync": self.sync,
            "enable_reports": False,
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
