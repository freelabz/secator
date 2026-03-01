# secator/ai/history.py
"""Chat history management for AI task - litellm format."""
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


SUMMARIZATION_PROMPT = """Summarize the following attack session history into a compact context.
Keep ONLY the essential information:
- Key findings (vulnerabilities, open ports, services, credentials)
- Important tool outputs (IPs, URLs, domains, versions discovered)
- Current attack progress and next steps
- Errors that affected the attack path

Discard verbose tool outputs, redundant information, and raw data dumps.
Keep the summary under {max_words} words. Use markdown formatting.

## History to summarize:

{history}

## Summary:"""


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
        self.messages.append({"role": "system", "content": content})

    def add_user(self, content: str) -> None:
        self.messages.append({"role": "user", "content": content})

    def add_assistant(self, content: str) -> None:
        self.messages.append({"role": "assistant", "content": content})

    def add_tool(self, content: str) -> None:
        self.messages.append({"role": "tool", "content": content})

    def to_messages(self) -> List[Dict[str, str]]:
        return self.messages.copy()

    def clear(self) -> None:
        self.messages = []

    def est_tokens(self) -> int:
        """Estimate token count (1 token ~ 4 chars)."""
        return sum(len(m.get("content", "")) for m in self.messages) // 4

    def maybe_summarize(self, model: str, api_base: Optional[str] = None, api_key: Optional[str] = None,
                        threshold: int = 30000) -> Tuple[bool, int, int]:
        """Summarize history if estimated token count exceeds threshold.

        Args:
            model: LLM model name
            api_base: Optional API base URL
            threshold: Token threshold to trigger summarization

        Returns:
            tuple: (summarized, old_tokens, new_tokens)
        """
        old_tokens = self.est_tokens()
        if old_tokens <= threshold:
            return False, old_tokens, old_tokens

        self._summarize_with_llm(model, api_base, api_key, threshold)
        new_tokens = self.est_tokens()
        return True, old_tokens, new_tokens

    def _summarize_with_llm(self, model: str, api_base: Optional[str] = None, api_key: Optional[str] = None,
                            threshold: int = 30000) -> None:
        """Summarize non-system messages using an LLM, keeping the initial system prompt intact."""
        if len(self.messages) <= 2:
            return

        # Preserve the initial system prompt, summarize everything else
        system_msgs = [m for m in self.messages if m["role"] == "system"]
        non_system_msgs = [m for m in self.messages if m["role"] != "system"]
        initial_system = system_msgs[0] if system_msgs else None

        if not non_system_msgs:
            return

        # Import here to avoid circular import
        from secator.ai.utils import call_llm
        from secator.rich import console

        # Account for system prompt size in budget
        system_tokens = len(initial_system["content"]) // 4 if initial_system else 0
        remaining_budget = threshold - system_tokens
        max_words = (remaining_budget * 60 // 100) // 2  # rough tokens-to-words ratio

        history_text = json.dumps(non_system_msgs, indent=None)
        prompt = SUMMARIZATION_PROMPT.format(history=history_text, max_words=max_words)
        from secator.utils import format_token_count
        token_str = format_token_count(self.est_tokens(), icon='arrow_up')
        with console.status(f"[bold orange3]Compacting chat history...[/] [gray42] • {token_str}[/]", spinner="dots"):
            result = call_llm([{"role": "user", "content": prompt}], model, 0.3, api_base, api_key)

        self.messages = []
        if initial_system:
            self.messages.append(initial_system)
        self.messages.append({"role": "user", "content": f"Summary of previous iterations:\n\n{result['content']}"})
