"""AI-powered code generation for Secator."""

import os
import re
import yaml
from pathlib import Path

from secator.config import CONFIG
from secator.output_types import Error, Info, Warning
from secator.rich import console


TASK_SYSTEM_PROMPT = """You are a programming assistant for Secator, a pentesting automation tool.

Before you begin, familiarize yourself with:
- Secator documentation at https://docs.freelabz.com
- Secator repository at https://github.com/freelabz/secator
- Existing task implementations in the secator/tasks/ directory
- Task categories defined in secator/tasks/_categories.py

## Task Implementation Guidelines

When implementing a task, follow these rules:

1. **Tool Selection Criteria**: Only integrate tools that are:
   - Fast and efficient
   - Well-maintained with active development
   - Have structured output (JSON, JSON lines, CSV, or XML preferred)
   - Widely recognized and used in the security community
   - Exceptions can be made for exceptional tools (like nmap) with custom parsers

2. **Code Structure**:
   - Use the @task() decorator
   - Don't use type annotations
   - Inherit from appropriate category class (Http, HttpCrawler, HttpFuzzer, ReconDns, ReconPort, ReconAsn, VulnHttp, etc.)
   - Define cmd, input_types, output_types, tags, file_flag, input_flag, json_flag, version_flag, opt_prefix if needed
   - Map options using opt_key_map and opt_value_map
   - Define on_cmd(self) static method to set additional command options if needed
   - Define on_json_loaded(self, item) static method and item_loaders=[JSONSerializer()] to yield Secator output types if the tool supports JSON output
   - Define on_line(self, line) static method to yield Secator output types if the tool doesn't support JSON output
   - Define install_cmd, install_version, install_github_bin, github_handle, install_github_version_prefix, and install_ignore_bin if needed
   - When yielding Secator output types, make sure to use the correct fields for the output type by looking up the schema in secator/output_types/<output_type>.py. Underscored fields should not be used as they are automatically set.

3. **Other considerations**:
   - Check if there is a similar tool already implemented in the Github repository and learn from it
   - Lookup the tool's documentation and usage examples, and if possible the --help output to understand all of it's options and flags
   - Lookup the tool's output format and how to parse it
   - Lookup the tool's installation method and how to install it

## Example Task Implementation

```python
from secator.decorators import task
from secator.definitions import DELAY, DOMAIN, HOST, PROXY, RATE_LIMIT, THREADS, TIMEOUT
from secator.output_types import Subdomain
from secator.serializers import JSONSerializer
from secator.tasks._categories import ReconDns


@task()
class example_tool(ReconDns):
    \"\"\"Tool description.\"\"\"
    cmd = 'example_tool'
    input_types = [HOST]
    output_types = [Subdomain]
    tags = ['dns', 'recon']
    file_flag = '-list'
    input_flag = '-domain'
    json_flag = '-json'
    opt_key_map = {
        DELAY: 'delay',
        PROXY: 'proxy',
        RATE_LIMIT: 'rate-limit',
        TIMEOUT: 'timeout',
        THREADS: 'threads'
    }
    item_loaders = [JSONSerializer()]
    install_version = 'v1.0.0'
    install_cmd = 'go install -v github.com/example/example_tool@[install_version]'
    github_handle = 'example/example_tool'
    proxychains = False
    proxy_http = True
    proxy_socks5 = False
    profile = 'io'

    @staticmethod
    def on_json_loaded(self, item):
        yield Subdomain(
            domain=item['domain'],
            host=item['host'],
            verified=item['verified'],
            sources=item['sources'],
            extra_data=item['extra_data']
        )
```

## Your Task

You will be asked to implement a task based on:
- A GitHub repository URL (fetch tool info from GitHub)
- A tool name (search the web to find the tool)
- A tool description (find the best matching tool)

Research the tool thoroughly, understand its:
- Command-line interface
- Output format
- Available options
- Installation method
- GitHub repository

Then generate a complete, production-ready task implementation file that follows all guidelines above.
"""  # noqa: E501

WORKFLOW_SYSTEM_PROMPT = """You are a programming assistant for Secator, a pentesting automation tool.

Before you begin, familiarize yourself with:
- Secator documentation at https://docs.freelabz.com
- Secator repository at https://github.com/freelabz/secator
- Existing workflow configurations in secator/configs/workflows/
- Available tasks in secator/tasks/

## Workflow Configuration Guidelines

Workflows in Secator chain multiple tasks together to accomplish a specific goal. They are defined in YAML format.

### Structure

```yaml
type: workflow
name: workflow_name
alias: short_alias
description: Short description
long_description: |
  Detailed multi-line description
  explaining what the workflow does
input_types:
  - host  # or url, ip, etc.

options:
  option_name:
    is_flag: True
    help: Option description
    default: False
    short: opt

tasks:
  task_name:
    description: What this task does
    option1: value1
    option2: value2
    if: conditional expression

  _group:
    task_name_2:
      description: Grouped task
    task_name_3:
      description: Another grouped task

  task_name_4:
    description: Task using outputs
    targets_:
      - url.url
      - type: subdomain
        field: host
        condition: subdomain.verified
```

### Key Concepts

1. **Task Chaining**: Tasks run sequentially and can use outputs from previous tasks
2. **Conditionals**: Use `if:` to conditionally run tasks based on options or outputs
3. **Task Groups**: Use `_group:` to run multiple tasks in parallel
4. **Target Selectors**: Use `targets_:` to feed outputs from previous tasks as inputs
5. **Options**: Define workflow-specific options that users can set

### Target Selectors

- Simple: `- url.url` (use url field from Url outputs)
- Complex:
  ```yaml
  - type: subdomain
    field: host
    condition: subdomain.verified
  ```

### Available Tasks

Common tasks you can use:
- **DNS Recon**: subfinder, dnsx, jswhois, getasn
- **Port Scanning**: nmap, naabu
- **HTTP Probing**: httpx
- **URL Discovery**: gau, katana, gospider, cariddi, waymore
- **Content Discovery**: ffuf, feroxbuster, dirsearch
- **Vulnerability Scanning**: nuclei, dalfox, wpscan, testssl
- **Information Gathering**: wafw00f, whois, sshaudit

## Your Task

You will receive a description of a workflow to create. Generate a complete, valid YAML workflow configuration that:
1. Chains appropriate tasks together
2. Uses proper task options and conditionals
3. Follows the structure and patterns of existing workflows
4. Includes clear descriptions
5. Uses appropriate input and output types
"""  # noqa: E501

SCAN_SYSTEM_PROMPT = """You are a programming assistant for Secator, a pentesting automation tool.

Before you begin, familiarize yourself with:
- Secator documentation at https://docs.freelabz.com
- Secator repository at https://github.com/freelabz/secator
- Existing scan configurations in secator/configs/scans/
- Available workflows in secator/configs/workflows/

## Scan Configuration Guidelines

Scans in Secator combine multiple workflows to provide comprehensive security
assessments. They are defined in YAML format.

### Structure

```yaml
type: scan
name: scan_name
description: Short description
long_description: |
  Detailed multi-line description
  explaining what the scan does
profile: default
input_types:
  - host  # or url, domain, etc.

workflows:
  workflow_name_1:
    option1: value1

  workflow_name_2:
    targets_:
      - type: target
        field: name
        condition: target.type == 'host'
      - type: subdomain
        field: host
        condition: subdomain.verified

  workflow_name_3:
    targets_:
      - url.url
```

### Key Concepts

1. **Workflow Composition**: Scans run multiple workflows in sequence
2. **Target Chaining**: Workflows can use outputs from previous workflows
3. **Comprehensive Coverage**: Scans provide full attack surface assessment
4. **Profiles**: Use profiles (default, pentest, etc.) to control execution

### Target Selectors

Same as workflows, use `targets_:` to chain outputs between workflows.

### Available Workflows

Common workflows you can use:
- **Reconnaissance**: domain_recon, subdomain_recon, host_recon, cidr_recon
- **Discovery**: url_crawl, url_dirsearch
- **Fuzzing**: url_fuzz, url_params_fuzz
- **Vulnerability**: url_vuln, url_bypass
- **Specialized**: wordpress, user_hunt, url_secrets_hunt, code_scan

## Your Task

You will receive a description of a scan to create. Generate a complete, valid
YAML scan configuration that:
1. Combines appropriate workflows in logical order
2. Uses proper target chaining between workflows
3. Follows the structure and patterns of existing scans
4. Includes clear descriptions
5. Provides comprehensive coverage for the stated goal
"""  # noqa: E501


def check_ai_addon():
    """Check if AI addon is installed."""
    try:
        import litellm  # noqa: F401
        return True
    except ImportError:
        console.print(Error(
            message='Missing AI addon. Please install it with: '
            'secator install addons ai'))
        return False


def get_model_and_key(model_override=None):
    """Get the AI model and API key from config or override."""
    model = model_override or CONFIG.ai.model
    api_key = CONFIG.ai.api_key

    # Check if we need an API key based on the model
    if not api_key and not model.startswith('ollama'):
        # Try to get API key from environment based on model provider
        if 'claude' in model or 'anthropic' in model:
            api_key = os.environ.get('ANTHROPIC_API_KEY', '')
        elif 'gpt' in model or 'openai' in model:
            api_key = os.environ.get('OPENAI_API_KEY', '')
        elif 'gemini' in model or 'google' in model:
            api_key = os.environ.get('GOOGLE_API_KEY', '')

        if not api_key:
            console.print(Error(
                message=f'No API key found for model {model}. Please set it '
                'with: secator config set ai.api_key <key>'))
            return None, None

    return model, api_key


def call_ai(prompt, system_prompt, model, api_key):
    """Call AI model with the given prompt."""
    try:
        import litellm
        from litellm import completion
        litellm.drop_params = True

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ]

        # Set API key in environment if provided
        if api_key:
            if 'claude' in model or 'anthropic' in model:
                os.environ['ANTHROPIC_API_KEY'] = api_key
            elif 'gpt' in model or 'openai' in model:
                os.environ['OPENAI_API_KEY'] = api_key
            elif 'gemini' in model or 'google' in model:
                os.environ['GOOGLE_API_KEY'] = api_key

        console.print(Info(message=f'Calling AI model: {model}'))
        response = completion(
            model=model,
            messages=messages,
            temperature=0.3,
        )

        return response.choices[0].message.content
    except Exception as e:
        console.print(Error(message=f'Error calling AI: {str(e)}'))
        return None


def extract_code_block(content, language='python'):
    """Extract code block from markdown-formatted response."""
    # Try to find code block with language specifier
    pattern = f'```{language}\\n(.*?)```'
    match = re.search(pattern, content, re.DOTALL)
    if match:
        return match.group(1).strip()

    # Try to find any code block
    pattern = '```\\n(.*?)```'
    match = re.search(pattern, content, re.DOTALL)
    if match:
        return match.group(1).strip()

    # Try to find code block with alternative markers
    pattern = '```.*?\\n(.*?)```'
    match = re.search(pattern, content, re.DOTALL)
    if match:
        return match.group(1).strip()

    # If no code block found, return the whole content
    return content.strip()


def generate_task(input_text, model=None):
    """Generate a task implementation based on input.

    Args:
            input_text: GitHub URL, tool name, or description
            model: AI model override
    """
    if not check_ai_addon():
        return False

    model, api_key = get_model_and_key(model)
    if not model:
        return False

    # Build the prompt
    prompt = (
        "I need you to implement a Secator task for the following:\n\n"
        f"{input_text}\n\n"
        "Please research this tool thoroughly. If it's a GitHub URL, analyze "
        "the repository. If it's a tool name or description, search for the "
        "tool and find its details.\n\n"
        "Once you understand the tool, generate a complete task implementation "
        "following the guidelines. Include:\n"
        "1. Proper imports\n"
        "2. The @task() decorator\n"
        "3. Correct class inheritance\n"
        "4. All required fields (cmd, input_types, output_types, tags, etc.)\n"
        "5. Option mappings (opt_key_map, opt_value_map)\n"
        "6. Output parsing (item_loaders, on_json_loaded, on_line, etc...)\n"
        "7. Installation information (install_cmd, install_version, github_handle)\n\n"
        "Make sure the implementation is production-ready and follows the "
        "exact patterns from the example and guidelines.\n\n"
        "Output ONLY the Python code, wrapped in ```python code blocks. "
        "Do not include any explanatory text outside the code block."
    )

    # Call AI
    response = call_ai(prompt, TASK_SYSTEM_PROMPT, model, api_key)
    if not response:
        return False

    # Extract code
    code = extract_code_block(response, 'python')

    # Extract task name from code
    match = re.search(r'class\s+(\w+)\s*\(', code)
    if not match:
        console.print(Error(message='Could not extract task name from generated code'))
        return False

    task_name = match.group(1)

    # Save to templates directory
    templates_dir = Path(CONFIG.dirs.templates)
    templates_dir.mkdir(parents=True, exist_ok=True)

    output_file = templates_dir / f'{task_name}.py'
    with open(output_file, 'w') as f:
        f.write(code)

    console.print(Info(
        message=f'Task implementation saved to: {output_file}'))
    console.print('\n[bold green]Generated code:[/]\n')

    # Print with syntax highlighting
    from rich.syntax import Syntax
    syntax = Syntax(code, 'python', theme='monokai', line_numbers=True)
    console.print(syntax)

    return True


def generate_workflow(description, model=None):
    """Generate a workflow configuration based on description."""
    if not check_ai_addon():
        return False

    model, api_key = get_model_and_key(model)
    if not model:
        return False

    # Build the prompt
    prompt = (
        "I need you to create a Secator workflow configuration for:\n\n"
        f"{description}\n\n"
        "Generate a complete, valid YAML workflow configuration that "
        "accomplishes this goal. The workflow should:\n"
        "1. Use appropriate tasks in the correct order\n"
        "2. Include proper task options and conditionals\n"
        "3. Use target selectors to chain outputs between tasks\n"
        "4. Follow the structure of existing workflows\n"
        "5. Include clear descriptions\n\n"
        "Output ONLY the YAML configuration, wrapped in ```yaml code blocks. "
        "Do not include any explanatory text outside the code block."
    )

    # Call AI
    response = call_ai(prompt, WORKFLOW_SYSTEM_PROMPT, model, api_key)
    if not response:
        return False

    # Extract code
    code = extract_code_block(response, 'yaml')

    # Extract workflow name from YAML
    try:
        config = yaml.safe_load(code)
        workflow_name = config.get('name', 'unnamed_workflow')
    except Exception as e:
        console.print(Warning(
            message=f'Could not parse YAML to extract name: {str(e)}'))
        workflow_name = 'unnamed_workflow'

    # Save to templates directory
    templates_dir = Path(CONFIG.dirs.templates)
    templates_dir.mkdir(parents=True, exist_ok=True)

    output_file = templates_dir / f'{workflow_name}.yaml'
    with open(output_file, 'w') as f:
        f.write(code)

    console.print(Info(
        message=f'Workflow configuration saved to: {output_file}'))
    console.print('\n[bold green]Generated configuration:[/]\n')

    # Print with syntax highlighting
    from rich.syntax import Syntax
    syntax = Syntax(code, 'yaml', theme='monokai', line_numbers=True)
    console.print(syntax)

    return True


def generate_scan(description, model=None):
    """Generate a scan configuration based on description."""
    if not check_ai_addon():
        return False

    model, api_key = get_model_and_key(model)
    if not model:
        return False

    # Build the prompt
    prompt = (
        "I need you to create a Secator scan configuration for:\n\n"
        f"{description}\n\n"
        "Generate a complete, valid YAML scan configuration that accomplishes "
        "this goal. The scan should:\n"
        "1. Combine appropriate workflows in logical order\n"
        "2. Use proper target chaining between workflows\n"
        "3. Follow the structure of existing scans\n"
        "4. Include clear descriptions\n"
        "5. Provide comprehensive coverage\n\n"
        "Output ONLY the YAML configuration, wrapped in ```yaml code blocks. "
        "Do not include any explanatory text outside the code block."
    )

    # Call AI
    response = call_ai(prompt, SCAN_SYSTEM_PROMPT, model, api_key)
    if not response:
        return False

    # Extract code
    code = extract_code_block(response, 'yaml')

    # Extract scan name from YAML
    try:
        config = yaml.safe_load(code)
        scan_name = config.get('name', 'unnamed_scan')
    except Exception as e:
        console.print(Warning(
            message=f'Could not parse YAML to extract name: {str(e)}'))
        scan_name = 'unnamed_scan'

    # Save to templates directory
    templates_dir = Path(CONFIG.dirs.templates)
    templates_dir.mkdir(parents=True, exist_ok=True)

    output_file = templates_dir / f'{scan_name}.yaml'
    with open(output_file, 'w') as f:
        f.write(code)

    console.print(Info(
        message=f'Scan configuration saved to: {output_file}'))
    console.print('\n[bold green]Generated configuration:[/]\n')

    # Print with syntax highlighting
    from rich.syntax import Syntax
    syntax = Syntax(code, 'yaml', theme='monokai', line_numbers=True)
    console.print(syntax)

    return True
