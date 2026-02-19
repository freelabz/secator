"""AI-powered penetration testing task using LiteLLM."""

import hashlib
import json
import logging
import os
import re
import signal
import subprocess
import time
from dataclasses import asdict
from typing import Any, Dict, Generator, List, Optional

import click

from secator.config import CONFIG
from secator.decorators import task
from secator.output_types import Error, Info, Tag, Vulnerability, Warning
from secator.runners import PythonRunner

logger = logging.getLogger(__name__)


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


def format_results_for_llm(results: List[Any], max_items: int = 100) -> str:
    """Format secator results into a structured prompt for the LLM."""
    if not results:
        return "No previous results available."

    formatted = []
    result_types: Dict[str, List] = {}

    # Group results by type
    for result in results[:max_items]:
        result_type = getattr(result, "_type", "unknown")
        if result_type not in result_types:
            result_types[result_type] = []
        result_types[result_type].append(result)

    for rtype, items in result_types.items():
        formatted.append(f"\n## {rtype.upper()} ({len(items)} items)")
        for item in items[:20]:  # Limit per type
            try:
                if hasattr(item, "__dict__"):
                    # Filter out internal fields
                    data = {
                        k: v
                        for k, v in asdict(item).items()
                        if not k.startswith("_") and v
                    }
                    formatted.append(f"  - {json.dumps(data, default=str)}")
                else:
                    formatted.append(f"  - {str(item)}")
            except Exception:
                formatted.append(f"  - {str(item)}")

    return "\n".join(formatted)


def get_llm_response(
    prompt: str,
    model: str = "gpt-4o-mini",
    system_prompt: str = "",
    temperature: float = 0.7,
    max_tokens: int = 4096,
    max_retries: int = 5,
    initial_delay: float = 1.0,
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
                )
                return response.choices[0].message.content
            except litellm.RateLimitError as e:
                last_exception = e
                if attempt < max_retries - 1:
                    delay = initial_delay * (2 ** attempt)  # Exponential backoff
                    logger.warning(f"Rate limit hit, retrying in {delay:.1f}s (attempt {attempt + 1}/{max_retries})")
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


SECATOR_CHEATSHEET = """
=== SECATOR CHEATSHEET ===

SYNTAX:
  secator x <task> <target> [options]     # run a task (x = execute)
  secator w <workflow> <target> [options] # run a workflow
  secator s <scan> <target> [options]     # run a scan

EXAMPLES:
  secator x httpx example.com             # run httpx task
  secator x nmap example.com -p 80,443    # run nmap with port option
  secator w url_crawl https://example.com # run url crawl workflow
  secator s host example.com              # run host scan
  secator s domain example.com            # run domain scan

INPUT TYPES:
  example.com              # single input
  host1,host2,host3        # comma-separated
  hosts.txt                # file input

COMMON OPTIONS:
  -rl 10                   # rate limit (req/sec)
  -delay 1                 # delay between requests
  -proxy http://127.0.0.1:8080
  -pf <profile>            # aggressive, passive, all_ports, full
  -o json                  # output format

USEFUL SCANS:
  secator s domain <DOMAIN>              # full domain recon
  secator s domain <DOMAIN> -pf passive  # passive only
  secator s host <HOST>                  # host recon

USEFUL WORKFLOWS:
  secator w subdomain_recon <DOMAIN>
  secator w url_crawl <URL>
  secator w url_fuzz <URL>
  secator w code_scan <PATH_OR_REPO>

PIPING:
  secator x subfinder example.com | secator x httpx | secator x nuclei

REFERENCE (verify options exist before using):
  Tasks: https://github.com/freelabz/secator/tree/main/secator/tasks
  Configs: https://github.com/freelabz/secator/tree/main/secator/configs

RULES:
  - ALWAYS use 'secator x <tool>' instead of raw tool commands
  - ONLY use options that exist (check task file if unsure)
"""

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

SYSTEM_PROMPTS = {
    "summarize": """You are a senior penetration tester analyzing security scan results.
Your task is to:
1. Summarize the key findings from the scan results
2. Identify potential attack paths based on discovered vulnerabilities, services, and endpoints
3. Prioritize findings by severity and exploitability
4. Highlight any interesting patterns or relationships between findings

Format your response with clear sections:
- **Executive Summary**: Brief overview of findings
- **Critical Findings**: High-severity issues requiring immediate attention
- **Attack Paths**: Potential exploitation chains
- **Recommendations**: Next steps for deeper testing

Be concise but thorough. Focus on actionable intelligence.""",
    "suggest": f"""You are a senior penetration tester recommending next steps for a security assessment.
Based on the scan results and targets, suggest specific Secator tasks to run next.

{SECATOR_CHEATSHEET}

Provide 3-5 specific secator commands with brief reasoning for each.
Include the actual target from the findings, not placeholders.""",
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
{{"action": "complete", "summary": "overall findings"}}

To stop immediately (e.g., if blocked or no further actions possible), respond with:
{{"action": "stop", "reason": "why stopping"}}""",
    "initial_recon": f"""You are a senior penetration tester starting a new security assessment.
Given the target(s), suggest an initial reconnaissance plan using Secator tasks.

{SECATOR_CHEATSHEET}

Suggest 2-3 initial commands to start the assessment.
Format each as: secator x <task> <target> [options]""",
}


@task()
class ai(PythonRunner):
    """AI-powered penetration testing assistant using LLM.

    Modes:
        - summarize: Analyze results and identify attack paths
        - suggest: Recommend next secator tasks to run (with optional execution)
        - attack: Autonomous attack loop with proof-of-concept validation

    Examples:
        secator x ai example.com --mode summarize    # Analyze target
        secator w host_recon example.com | secator x ai --mode suggest  # Get suggestions
        secator x ai example.com --mode suggest --run  # Run suggested tasks
        secator x ai example.com --mode attack --dry-run  # Dry-run attack
    """

    output_types = [Vulnerability, Tag, Info, Warning, Error]
    tags = ["ai", "analysis", "pentest"]
    input_types = []  # Accept any input type
    install_cmd = "pip install litellm"

    opts = {
        "mode": {
            "type": str,
            "default": "summarize",
            "help": "Operation mode: summarize, suggest, or attack",
        },
        "model": {
            "type": str,
            "default": "gpt-4o-mini",
            "help": "LLM model to use (via LiteLLM)",
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
        "prompt": {
            "type": str,
            "default": None,
            "short": "p",
            "help": "Additional instructions to include in the initial prompt",
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

        mode = self.run_opts.get("mode", "summarize")
        model = self.run_opts.get("model", "gpt-4o-mini")
        sensitive = self.run_opts.get("sensitive", True)
        sensitive_list = self.run_opts.get("sensitive_list")

        # Get results from previous runs
        results = self._previous_results or self.results

        # Targets are from self.inputs
        targets = self.inputs

        if not results and not targets:
            yield Warning(
                message="No results or targets available for AI analysis. Provide targets as input."
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
                context_text, model, encryptor, results, targets
            )
        elif mode == "suggest":
            yield from self._mode_suggest(
                context_text, model, encryptor, results, targets
            )
        elif mode == "attack":
            yield from self._mode_attack(
                context_text, model, encryptor, results, targets
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
    ) -> Generator:
        """Summarize results and identify attack paths."""
        custom_prompt = self.run_opts.get("prompt", "")

        # If no results but have targets, suggest initial recon
        if not results and targets:
            yield Info(
                message="No previous results. Providing initial reconnaissance suggestions."
            )
            prompt = f"""Analyze these targets and suggest an initial penetration testing approach:

## Targets
{", ".join(targets)}

Provide a brief assessment and initial steps."""
            system_prompt = SYSTEM_PROMPTS["initial_recon"]
        else:
            prompt = f"""Analyze the following penetration test results and provide a summary:

{context_text}

Identify key findings, potential attack paths, and prioritize by severity."""
            system_prompt = SYSTEM_PROMPTS["summarize"]

        # Add custom prompt if provided
        if custom_prompt:
            prompt += f"\n\n## Additional Instructions\n{custom_prompt}"

        verbose = self.run_opts.get("verbose", False)

        if verbose:
            yield Info(message=f"[PROMPT] {_truncate(prompt)}")

        try:
            response = get_llm_response(
                prompt=prompt,
                model=model,
                system_prompt=system_prompt,
                temperature=float(self.run_opts.get("temperature", 0.7)),
            )

            # Decrypt sensitive data in response
            if self.run_opts.get("sensitive", True):
                response = encryptor.decrypt(response)

            # Always show AI response (contains valuable analysis)
            yield Info(message=f"[AGENT] {_truncate(response)}")

            yield Tag(
                name="ai_summary",
                value=response,
                match="summarize",
                category="ai",
                extra_data={"model": model, "mode": "summarize"},
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
    ) -> Generator:
        """Suggest next secator tasks to run."""
        run_suggestions = self.run_opts.get("run", False)
        auto_yes = self.run_opts.get("yes", False)
        in_ci = _is_ci()
        verbose = self.run_opts.get("verbose", False)
        custom_prompt = self.run_opts.get("prompt", "")

        # Build prompt based on whether we have results
        if not results and targets:
            prompt = f"""You are starting a new penetration test on these targets:

## Targets
{", ".join(targets)}

Suggest initial reconnaissance commands to run."""
            system_prompt = SYSTEM_PROMPTS["initial_recon"]
        else:
            prompt = f"""Based on these penetration test results, suggest specific Secator commands to run next:

{context_text}

Provide actionable commands with reasoning for each suggestion."""
            system_prompt = SYSTEM_PROMPTS["suggest"]

        # Add custom prompt if provided
        if custom_prompt:
            prompt += f"\n\n## Additional Instructions\n{custom_prompt}"

        if verbose:
            yield Info(message=f"[PROMPT] {_truncate(prompt)}")

        try:
            response = get_llm_response(
                prompt=prompt,
                model=model,
                system_prompt=system_prompt,
                temperature=float(self.run_opts.get("temperature", 0.7)),
            )

            # Decrypt sensitive data in response
            if self.run_opts.get("sensitive", True):
                response = encryptor.decrypt(response)

            # Always show AI response (contains valuable suggestions)
            yield Info(message=f"[AGENT] {_truncate(response)}")

            # Extract suggested commands
            commands = self._extract_commands(response)

            yield Tag(
                name="ai_suggestions",
                value=response,
                match="suggest",
                category="ai",
                extra_data={
                    "model": model,
                    "mode": "suggest",
                    "suggested_commands": commands,
                },
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
    ) -> Generator:
        """Execute reactive attack loop to exploit vulnerabilities."""
        max_iterations = int(self.run_opts.get("max_iterations", 10))
        dry_run = self.run_opts.get("dry_run", False)
        verbose = self.run_opts.get("verbose", False)
        custom_prompt = self.run_opts.get("prompt", "")

        yield Info(
            message=f"Starting attack mode (max {max_iterations} iterations, dry_run={dry_run})"
        )
        yield Info(message=f"Scope restricted to: {', '.join(targets)}")

        # Build attack context
        attack_context = {
            "iteration": 0,
            "successful_attacks": [],
            "failed_attacks": [],
            "validated_vulns": [],
            "targets": targets,
        }

        # Encrypt targets for prompts if sensitive data encryption enabled
        sensitive = self.run_opts.get("sensitive", True)
        targets_str = ", ".join(targets)
        if sensitive:
            targets_str = encryptor.encrypt(targets_str)

        # Initial prompt - if no results, start with recon
        if not results and targets:
            prompt = f"""You are starting authorized penetration testing on these targets:

## Targets
{targets_str}

## Instructions
Start with reconnaissance to identify attack surface. Respond with a JSON action."""
        else:
            prompt = f"""You are conducting authorized penetration testing.

## Current Findings
{context_text}

## Targets (Scope)
{targets_str}

## Instructions
Analyze the findings and plan your first attack. Respond with a JSON action."""

        # Create custom prompt suffix to include in all prompts
        custom_prompt_suffix = ""
        if custom_prompt:
            custom_prompt_suffix = f"\n\n## IMPORTANT - User Instructions (MUST FOLLOW)\n{custom_prompt}"
            prompt += custom_prompt_suffix

        for iteration in range(max_iterations):
            attack_context["iteration"] = iteration + 1
            yield Info(message=f"Attack iteration {iteration + 1}/{max_iterations}")

            try:
                if verbose:
                    yield Info(message=f"[PROMPT] {_truncate(prompt)}")

                response = get_llm_response(
                    prompt=prompt,
                    model=model,
                    system_prompt=SYSTEM_PROMPTS["attack"],
                    temperature=0.3,  # Lower temperature for attack mode
                )

                # Decrypt sensitive data
                if self.run_opts.get("sensitive", True):
                    response = encryptor.decrypt(response)

                # Always show AI response (contains reasoning and actions)
                yield Info(message=f"[AGENT] {_truncate(response)}")

                # Parse action from response
                action = self._parse_attack_action(response)

                if not action:
                    yield Warning(message="Could not parse action from LLM response")
                    # Resend previous context with the invalid response so LLM can fix it
                    encrypted_context = json.dumps(attack_context)
                    encrypted_response = response[:2000]
                    if sensitive:
                        encrypted_context = encryptor.encrypt(encrypted_context)
                        encrypted_response = encryptor.encrypt(encrypted_response)
                    prompt = f"""Your previous response was not valid JSON and could not be parsed.

Your response was:
{encrypted_response}

Please respond with a valid JSON action in one of these formats:
- {{"action": "execute", "type": "task|workflow|scan", "name": "...", "targets": [...], "opts": {{...}}, "reasoning": "...", "expected_outcome": "..."}}
- {{"action": "execute", "type": "shell", "command": "...", "target": "...", "reasoning": "...", "expected_outcome": "..."}}
- {{"action": "validate", "vulnerability": "...", "target": "...", "proof": "...", "severity": "...", "reproduction_steps": [...]}}
- {{"action": "complete", "summary": "..."}}
- {{"action": "stop", "reason": "..."}}

Current attack context:
{encrypted_context}""" + custom_prompt_suffix
                    continue

                action_type = action.get("action", "")

                if action_type == "complete":
                    yield Info(message="Attack loop completed")
                    yield Tag(
                        name="attack_summary",
                        value=action.get("summary", "Attack sequence completed"),
                        match="attack",
                        category="ai",
                        extra_data={
                            "iterations": iteration + 1,
                            "successful_attacks": len(
                                attack_context["successful_attacks"]
                            ),
                            "validated_vulns": len(attack_context["validated_vulns"]),
                        },
                    )
                    break

                elif action_type == "stop":
                    reason = action.get("reason", "No reason provided")
                    yield Warning(message=f"Attack loop stopped: {reason}")
                    yield Tag(
                        name="attack_stopped",
                        value=reason,
                        match="attack",
                        category="ai",
                        extra_data={
                            "iterations": iteration + 1,
                            "successful_attacks": len(
                                attack_context["successful_attacks"]
                            ),
                            "validated_vulns": len(attack_context["validated_vulns"]),
                        },
                    )
                    break

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
                            prompt = f"Targets {out_of_scope} are out of scope. Only test: {targets_str}. Choose another action.\n\nContext:\n{encrypted_context}" + custom_prompt_suffix
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
{encrypted_context}""" + custom_prompt_suffix
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

Analyze the results and decide next action (execute, validate, stop, or complete).""" + custom_prompt_suffix

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
                            prompt = f"Target {target} was out of scope. Only test: {targets_str}. Choose another action.\n\nContext:\n{encrypted_context}" + custom_prompt_suffix
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

Analyze the output and decide next action (execute, validate, stop, or complete).""" + custom_prompt_suffix

                    else:
                        yield Warning(message=f"Unknown execute type: {exec_type}")
                        prompt = f"Unknown execute type '{exec_type}'. Use: task, workflow, scan, or shell." + custom_prompt_suffix
                        continue

                elif action_type == "validate":
                    vuln_name = action.get("vulnerability", "Unknown")
                    target = action.get("target", "")
                    proof = action.get("proof", "")
                    severity = action.get("severity", "medium")
                    steps = action.get("reproduction_steps", [])

                    attack_context["validated_vulns"].append(
                        {
                            "name": vuln_name,
                            "severity": severity,
                            "target": target,
                        }
                    )

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

                    # Encrypt context for LLM prompt if sensitive encryption enabled
                    encrypted_context = json.dumps(attack_context)
                    if sensitive:
                        encrypted_context = encryptor.encrypt(encrypted_context)

                    prompt = f"""Vulnerability validated: {vuln_name}

Context:
{encrypted_context}

Continue testing or mark complete if all attack paths are exhausted.""" + custom_prompt_suffix

                elif action_type == "report":
                    yield Tag(
                        name="attack_report",
                        value=action.get("content", ""),
                        match="attack",
                        category="ai",
                        extra_data=attack_context,
                    )
                    # Encrypt context for LLM prompt if sensitive encryption enabled
                    encrypted_context = json.dumps(attack_context)
                    if sensitive:
                        encrypted_context = encryptor.encrypt(encrypted_context)
                    prompt = f"Report noted. Continue with next action.\n\nContext:\n{encrypted_context}" + custom_prompt_suffix

                else:
                    yield Warning(message=f"Unknown action type: {action_type}")
                    prompt = f"Unknown action '{action_type}'. Use: execute, validate, report, stop, or complete." + custom_prompt_suffix

            except Exception as e:
                yield Error(
                    message=f"Attack iteration {iteration + 1} failed: {str(e)}"
                )
                attack_context["failed_attacks"].append(str(e))
                # Encrypt context for LLM prompt if sensitive encryption enabled
                encrypted_context = json.dumps(attack_context)
                if sensitive:
                    encrypted_context = encryptor.encrypt(encrypted_context)
                prompt = f"Previous action failed with error: {str(e)}. Try a different approach.\n\nContext:\n{encrypted_context}" + custom_prompt_suffix

        # Final summary if we hit max iterations
        if attack_context["iteration"] >= max_iterations:
            yield Warning(message=f"Max iterations ({max_iterations}) reached")
            yield Tag(
                name="attack_summary",
                value="Attack loop reached maximum iterations",
                match="attack",
                category="ai",
                extra_data=attack_context,
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

    def _parse_attack_action(self, response: str) -> Optional[Dict]:
        """Parse JSON action from LLM response."""
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            pass

        # Try to find JSON in code blocks
        json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", response, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass

        # Try to find raw JSON object
        json_match = re.search(r'\{[^{}]*"action"[^{}]*\}', response, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass

        return None

    def _is_in_scope(self, target: str, scope_list: List[str]) -> bool:
        """Check if target is within defined scope."""
        if not scope_list:
            return True
        target_lower = target.lower()
        for scope_item in scope_list:
            scope_lower = scope_item.lower()
            # Check if target contains or matches scope item
            if scope_lower in target_lower or target_lower in scope_lower:
                return True
        return False

    def _execute_command(self, command: str) -> str:
        """Execute a command and return output."""
        try:
            # Security: only allow specific commands
            allowed_prefixes = ["secator ", "curl ", "wget ", "nmap ", "httpx "]
            if not any(command.startswith(p) for p in allowed_prefixes):
                return f"Command not allowed: {command}. Only secator, curl, wget, nmap, httpx commands permitted."

            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=120,
            )
            output = result.stdout + result.stderr

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
