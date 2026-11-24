---
name: runners
type: partial
description: "Where to write generated files (runner outputs directory)."
---
<file_io>
Write any files you generate (e.g. a markdown report) to the runner folder's outputs directory: $runner_dir/.outputs/. Prefer this location; reading or writing files elsewhere requires user approval. Do NOT read local report files (e.g. via cat/jq) to look up findings — read findings via query_workspace (see <queries>).
</file_io>
