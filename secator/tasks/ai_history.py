"""Chat history management for AI attack mode."""
from dataclasses import dataclass, field
from typing import List, Dict


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
