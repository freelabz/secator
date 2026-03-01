# AI Compact Library Reference Design

## Problem

The AI task refactor (ai.py from ~4000 to ~300 lines) lost important features that helped the AI make better decisions:

1. **Task options** - AI doesn't know valid options, can't self-correct
2. **Task descriptions** - AI doesn't know what tools do
3. **Wordlist reference** - AI doesn't know available wordlists
4. **Output type fields** - AI doesn't know what fields to query
5. **Query operators** - AI doesn't know $regex, $in, $contains, etc.
6. **Profiles** - AI doesn't know about aggressive/stealth/passive profiles

## Solution

Re-add the library reference in a compact pipe-delimited format to minimize token usage while providing complete information.

## Format

```
TASKS:
httpx|HTTP web server probing|ports,threads,rate_limit,header,proxy
nmap|Network port scanner|ports,scripts,version,timing
nuclei|Vulnerability scanner|templates,tags,severity,rate_limit

WORKFLOWS:
host_recon|Host reconnaissance
vuln_scan|Vulnerability scanning

PROFILES:
aggressive|Fast scanning, higher rate limits
stealth|Slow scanning, evasion techniques
passive|No active probing, OSINT only

WORDLISTS:
bo0m_fuzz
raft_large_dirs
common_passwords

OUTPUT_TYPES:
vulnerability|name,severity,confidence,matched_at,tags
url|url,host,port,status_code,content_type

OPTION_FORMATS:
header|key1:value1;;key2:value2|Multiple headers separated by ;;
proxy|http://host:port|HTTP/SOCKS proxy URL
wordlist|name_or_path|Use predefined name above or file path
```

## Implementation

### File: `secator/tasks/ai_prompts.py`

**New functions:**

1. `build_tasks_reference()` - dynamic task list with descriptions + options
2. `build_workflows_reference()` - dynamic workflow list with descriptions
3. `build_profiles_reference()` - dynamic profile list with descriptions
4. `build_wordlists_reference()` - wordlist names from CONFIG.wordlists
5. `build_output_types_reference()` - output types with queryable fields
6. `build_library_reference()` - combines all sections

**New constants:**

- `OPTION_FORMATS` - static string with format hints for complex options

**Updated functions:**

- `get_system_prompt()` - call `build_library_reference()` and format into prompt

### Updated SYSTEM_ATTACK Prompt

```python
SYSTEM_ATTACK = """Security testing assistant. Execute actions against provided targets.

RESPONSE FORMAT:
1. Brief reasoning (2-3 sentences max)
2. JSON array of actions

ACTIONS:
- task: {{"action":"task","name":"<tool>","targets":[...],"opts":{{}}}}
- workflow: {{"action":"workflow","name":"<name>","targets":[...],"opts":{{"profiles":["aggressive"]}}}}
- shell: {{"action":"shell","command":"<cmd>"}}
- query: {{"action":"query","type":"<output_type>","filter":{{}}}}
- done: {{"action":"done","reason":"<why>"}}

RULES:
- One action array per response
- Never invent tool output
- Use workspace queries to get historical data for context
- Targets are encrypted as [HOST:xxxx] - use as-is
- Only use options listed below for each task
- To use profiles, add "profiles": ["name"] in opts

{library_reference}

QUERY OPERATORS: $in, $regex, $contains, $gt, $lt, $ne
Example: {{"action":"query","type":"vulnerability","filter":{{"severity":{{"$in":["critical","high"]}}}}}}
"""
```

## Token Impact

- Current: ~100 tokens (just tool names)
- New: ~400-500 tokens (full reference)
- Old implementation: ~800+ tokens

## Files Unchanged

- `secator/tasks/ai.py` - already calls `get_system_prompt()`
- `secator/tasks/ai_actions.py` - unchanged
- Existing tests should still pass
