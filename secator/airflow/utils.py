"""Shared utilities for the secator Airflow integration.

Provides serialization/deserialization of secator OutputType objects for XCom
transport, target extraction from upstream results (replaces the `targets_:`
extractor system), and result deduplication.
"""

import logging

from secator.output_types import OUTPUT_TYPES, FINDING_TYPES

logger = logging.getLogger(__name__)

# Build a lookup map: output type name -> class
_TYPE_MAP = {t.get_name(): t for t in OUTPUT_TYPES}


def serialize_results(results):
    """Convert a list of OutputType instances to JSON-serializable dicts for XCom.

    Args:
        results (list): Mix of OutputType instances, dicts, or strings.

    Returns:
        list[dict]: Serialized results.
    """
    serialized = []
    for item in results:
        if hasattr(item, 'toDict'):
            serialized.append(item.toDict())
        elif isinstance(item, dict):
            serialized.append(item)
        # Skip raw strings / non-serializable items
    return serialized


def deserialize_results(results):
    """Reconstruct OutputType instances from XCom dicts.

    Args:
        results (list): List of dicts with `_type` discriminator.

    Returns:
        list: Mix of OutputType instances (where possible) and raw dicts.
    """
    deserialized = []
    for item in results:
        if isinstance(item, dict) and '_type' in item:
            cls = _TYPE_MAP.get(item['_type'])
            if cls:
                try:
                    deserialized.append(cls(**item))
                    continue
                except (TypeError, KeyError):
                    pass
        deserialized.append(item)
    return deserialized


def extract_targets(results, extractors):
    """Apply target extractors to a list of results.

    This replaces the `targets_:` extraction logic from:
      - secator/runners/_helpers.py::run_extractors()
      - secator/celery.py::mark_runner_started()

    Extractors format (from YAML):
        [{'type': 'url', 'field': 'url', 'condition': 'item.status_code == 200'}]

    Shortcut string format:
        ['subdomain.host', 'url.url']

    Args:
        results (list): Upstream results (dicts or OutputType instances).
        extractors (list): Extractor definitions.

    Returns:
        list[str]: Extracted target strings.
    """
    if not extractors:
        return []

    targets = []
    seen = set()

    for extractor in extractors:
        # Parse extractor - can be dict or shortcut string
        if isinstance(extractor, dict):
            target_type = extractor.get('type')
            field = extractor.get('field')
            condition = extractor.get('condition')
        elif isinstance(extractor, str) and '.' in extractor:
            parts = extractor.split('.', 1)
            target_type = parts[0]
            field = parts[1]
            condition = None
        else:
            logger.warning("Invalid extractor format: %s", extractor)
            continue

        for result in results:
            # Get result type
            if isinstance(result, dict):
                result_type = result.get('_type', '')
            elif hasattr(result, '_type'):
                result_type = result._type
            else:
                continue

            if result_type != target_type:
                continue

            # Get field value — handle template fields like '{host}:{port}'
            is_template = '{' in field and '}' in field
            if is_template:
                try:
                    if isinstance(result, dict):
                        value = field.format(**result)
                    elif hasattr(result, 'toDict'):
                        value = field.format(**result.toDict())
                    else:
                        value = None
                except (KeyError, IndexError, ValueError):
                    value = None
            else:
                if isinstance(result, dict):
                    value = result.get(field)
                else:
                    value = getattr(result, field, None)

            if not value or value in seen:
                continue

            # Evaluate condition if present
            if condition:
                try:
                    # Build safe evaluation context
                    if isinstance(result, dict):
                        from types import SimpleNamespace
                        item = SimpleNamespace(**result)
                    else:
                        item = result
                    eval_ctx = {'item': item, target_type: item, 'len': len}
                    safe_globals = {'__builtins__': {'len': len}}
                    if not eval(condition, safe_globals, eval_ctx):
                        continue
                except Exception as e:
                    logger.debug("Condition eval failed for %s: %s", condition, e)
                    continue

            seen.add(value)
            targets.append(value)

    return targets


def deduplicate_results(results):
    """Deduplicate a list of result dicts by _uuid.

    Args:
        results (list[dict]): Results with _uuid fields.

    Returns:
        list[dict]: Deduplicated results.
    """
    seen = set()
    deduped = []
    for result in results:
        uuid = result.get('_uuid') if isinstance(result, dict) else getattr(result, '_uuid', None)
        if uuid:
            if uuid in seen:
                continue
            seen.add(uuid)
        deduped.append(result)
    return deduped


def flatten_results(results):
    """Flatten nested result lists (e.g., from parallel task groups).

    Handles the case where Airflow returns [[results_from_task1], [results_from_task2]].

    Args:
        results: Potentially nested list of results.

    Returns:
        list: Flat list of results.
    """
    if not isinstance(results, list):
        return [results] if results else []
    flat = []
    for item in results:
        if isinstance(item, list):
            flat.extend(flatten_results(item))
        elif isinstance(item, dict) and 'results' in item:
            flat.extend(flatten_results(item['results']))
        else:
            flat.append(item)
    return flat


def get_finding_counts(results):
    """Count findings by type.

    Args:
        results (list[dict]): Serialized results.

    Returns:
        dict[str, int]: Type name to count mapping.
    """
    finding_type_names = {t.get_name() for t in FINDING_TYPES}
    counts = {}
    for result in results:
        _type = result.get('_type') if isinstance(result, dict) else getattr(result, '_type', None)
        if _type and _type in finding_type_names:
            counts[_type] = counts.get(_type, 0) + 1
    return counts
