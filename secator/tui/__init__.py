"""secator TUI — a reusable Textual rendering layer.

Modular so it can back more than the AI task later (normal task / workflow output):
- :mod:`secator.tui.render`  — item -> Rich renderable helpers (OutputType ``__rich__``)
- :mod:`secator.tui.widgets` — reusable widgets (collapsible runner panel, prompts, …)
- :mod:`secator.tui.app`     — the generic :class:`~secator.tui.app.TUIApp` shell
- :mod:`secator.tui.ai`      — the AI frontend (:class:`~secator.tui.ai.AITUI`)

Textual is an OPTIONAL dependency, so submodules are imported lazily (on the TUI path)
rather than eagerly here, keeping ``import secator.tui`` free of a hard textual import.
"""
