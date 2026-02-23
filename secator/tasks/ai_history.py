"""Chat history management for AI attack mode."""
from dataclasses import dataclass, field
from typing import Callable, List, Dict


@dataclass
class ChatHistory:
    """Manages chat history with role-based messages."""

    messages: List[Dict[str, str]] = field(default_factory=list)

    def add_assistant(self, content: str) -> None:
        """Add an assistant message."""
        self.messages.append({"role": "assistant", "content": content})

    def add_tool(self, content: str) -> None:
        """Add a tool response message."""
        self.messages.append({"role": "tool", "content": content})

    def add_user(self, content: str) -> None:
        """Add a user message."""
        self.messages.append({"role": "user", "content": content})

    def to_messages(self) -> List[Dict[str, str]]:
        """Return all messages as a list."""
        return self.messages.copy()

    def summarize(self, summarizer: Callable, keep_last: int = 4) -> None:
        """Summarize older messages, keeping the last N messages verbatim.

        Args:
            summarizer: Callable that takes messages list and returns summary string
            keep_last: Number of recent messages to keep verbatim (default: 4 = 2 iterations)
        """
        if len(self.messages) <= keep_last:
            return  # Nothing to summarize

        # Split messages
        messages_to_summarize = self.messages[:-keep_last]
        messages_to_keep = self.messages[-keep_last:]

        # Generate summary
        summary_text = summarizer(messages_to_summarize)

        # Rebuild messages with summary first
        self.messages = [
            {"role": "system", "content": summary_text}
        ] + messages_to_keep
