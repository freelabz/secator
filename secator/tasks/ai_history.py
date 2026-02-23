# secator/tasks/ai_history.py
"""Chat history management for AI task - litellm format."""
from dataclasses import dataclass, field
from typing import Callable, Dict, List


SUMMARIZATION_PROMPT = """Summarize the following attack session history concisely.
Focus on:
- Commands/tools executed
- Key findings (vulnerabilities, open ports, services)
- Errors or failures
- Current attack progress

Keep the summary under 500 words. Use markdown formatting.

## History to summarize:

{history}

## Summary:"""


def create_llm_summarizer(
    model: str,
    api_base: str = None,
    temperature: float = 0.3,
) -> Callable[[List[Dict[str, str]]], str]:
    """Create a summarizer function that uses an LLM.

    Args:
        model: LLM model name
        api_base: Optional API base URL
        temperature: LLM temperature (default: 0.3 for factual summaries)

    Returns:
        Callable that takes messages and returns summary string
    """
    def summarizer(messages: List[Dict[str, str]]) -> str:
        # Import here to avoid circular import
        from secator.tasks.ai import call_llm

        # Format messages for prompt
        history_text = ""
        for msg in messages:
            role = msg["role"].upper()
            content = msg["content"]
            history_text += f"**{role}:**\n{content}\n\n"

        prompt = SUMMARIZATION_PROMPT.format(history=history_text)

        # Build messages for call_llm
        llm_messages = [{"role": "user", "content": prompt}]
        result = call_llm(llm_messages, model, temperature, api_base)

        return f"## Summary of previous iterations\n\n{result['content']}"

    return summarizer


@dataclass
class ChatHistory:
    """Manages chat history in litellm message format.

    This is a thin wrapper around a list of message dicts that can be
    passed directly to litellm.completion().

    Attributes:
        messages: List of message dicts with 'role' and 'content' keys
    """

    messages: List[Dict[str, str]] = field(default_factory=list)

    def add_system(self, content: str) -> None:
        """Add a system message.

        Args:
            content: System prompt content
        """
        self.messages.append({"role": "system", "content": content})

    def add_user(self, content: str) -> None:
        """Add a user message (should be JSON for consistency).

        Args:
            content: User message content (typically compact JSON)
        """
        self.messages.append({"role": "user", "content": content})

    def add_assistant(self, content: str) -> None:
        """Add an assistant message (markdown + JSON).

        Args:
            content: Assistant response content
        """
        self.messages.append({"role": "assistant", "content": content})

    def add_tool(self, content: str) -> None:
        """Add a tool response message.

        Args:
            content: Tool output content
        """
        self.messages.append({"role": "tool", "content": content})

    def to_messages(self) -> List[Dict[str, str]]:
        """Return messages for litellm completion().

        Returns:
            Copy of the messages list (safe for modification)
        """
        return self.messages.copy()

    def clear(self) -> None:
        """Clear all messages."""
        self.messages = []

    def summarize(self, summarizer: Callable, keep_last: int = 4) -> None:
        """Summarize older messages, keeping recent ones.

        Args:
            summarizer: Function that takes messages list and returns summary string
            keep_last: Number of recent messages to keep verbatim (default: 4)
        """
        if len(self.messages) <= keep_last:
            return

        to_summarize = self.messages[:-keep_last]
        to_keep = self.messages[-keep_last:]

        summary = summarizer(to_summarize)

        self.messages = [
            {"role": "system", "content": f"Previous context:\n{summary}"}
        ] + to_keep
