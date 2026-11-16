"""AI tool: `query_workspace`."""
from secator.ai.tools.base import BaseTool, _DESCRIPTION_SCHEMA, _QUERY_MODES


class QueryWorkspace(BaseTool):
	name = "query_workspace"
	action = "query"
	modes = _QUERY_MODES
	auto_allow = True
	handler = "_handle_query"
	schema = {
		"type": "function",
		"function": {
			"name": "query_workspace",
			"description": "Query the workspace database for stored security findings using MongoDB-style queries. "
			               "Example (good): query_workspace(query={'_type':'vulnerability','severity':{'$in':['high','critical']}}, "  # noqa: E501
			               "description='Review high/critical vulns'). "
			               "Bad: query_workspace() — no query; query_workspace(query={}) — unscoped, returns noise.",
			"parameters": {
				"type": "object",
				"properties": {
					"query": {
						"type": "object",
						"description": "MongoDB-style query object (e.g. {\"_type\": \"vulnerability\", \"severity\": {\"$in\": [\"critical\", \"high\"]}})."  # noqa: E501
					},
					"description": _DESCRIPTION_SCHEMA,
					"limit": {
						"type": "integer",
						"description": "Maximum number of results to return.",
						"default": 100
					},
					"offset": {
						"type": "integer",
						"description": "Skip the first N results; use with limit to page through large result sets. "  # noqa: E501
						               "When a full page is returned, the response says the next offset to use.",
						"default": 0
					},
					"group": {
						"type": "boolean",
						"description": "Return aggregated group representatives (one per group, with a _group_count "  # noqa: E501
						               "member count + aggregated targets) instead of every finding — a compact overview "  # noqa: E501
						               "that saves context. Requires a single _type in the query. Each representative is "  # noqa: E501
						               "grouped by that type's key field (shown on the row, e.g. vulnerability->name, "  # noqa: E501
						               "port->host); drill into a group by re-querying that field — NOT the _uuid, which "  # noqa: E501
						               "identifies only the one representative finding.",
						"default": False
					}
				},
				"required": ["query", "description"]
			}
		}
	}
