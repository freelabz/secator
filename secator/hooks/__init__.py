"""Drivers: modules exposing runner hooks, enabled with ``--driver <name>``.

A driver module (built-in here, or an external ``.py`` file in the templates directory) defines
``HOOKS = {Task: {'on_item': [fn], ...}, Workflow: {...}, Scan: {...}}``. Each hook is called as
``fn(runner, *args)``; item hooks return the (possibly mutated) item.

Hook events: those in ``secator.runners._base.HOOKS``, plus ``on_item_update(runner, item)``,
fired when the ``ai`` task updates an existing finding (``update_finding``, ``mark_vuln_*``) with
the updated item. Persistence drivers do not implement it: the store write is the persistence.

Hooks run phase by phase, for every event. A driver picks its phase with a module-level
``HOOK_PHASE``:

- ``'pre'`` (default): before the persistence drivers, so item mutations are persisted. Pre hooks
  run synchronously in the runner: keep network calls short (small HTTP timeouts).
- ``'post'``: after the persistence drivers, e.g. relays and notifications (``api``, ``discord``).

The persistence drivers (``definitions.PERSISTENCE_DRIVERS``) run in between. A failing pre /
post hook never aborts the remaining hooks, even with ``raise_on_error``: it yields an Error and
the item is passed on as the previous hook returned it (in-place mutations made before the
failure are still persisted).
"""
