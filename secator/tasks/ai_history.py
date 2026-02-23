"""Chat history management for AI attack mode."""
from dataclasses import dataclass, field
from typing import Callable, List, Dict


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
        from secator.tasks.ai import get_llm_response

        # Format messages for prompt
        history_text = ""
        for msg in messages:
            role = msg["role"].upper()
            content = msg["content"]
            history_text += f"**{role}:**\n{content}\n\n"

        prompt = SUMMARIZATION_PROMPT.format(history=history_text)

        summary = get_llm_response(
            prompt=prompt,
            model=model,
            api_base=api_base,
            temperature=temperature,
        )

        return f"## Summary of previous iterations\n\n{summary}"

    return summarizer


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
