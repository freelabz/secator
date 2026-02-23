"""Prompt builder for AI attack mode."""
from dataclasses import dataclass
from typing import Any, Dict, List

from secator.tasks.ai_history import ChatHistory


USER_PROMPT_TEMPLATE = """## Targets
{targets_list}

## Instructions
{instructions}
"""

LOOP_QUERY_TEMPLATE = """Iteration {iteration}/{max_iterations}. Based on the history above, decide your next actions.
Respond with a JSON array of actions."""


@dataclass
class PromptBuilder:
    """Builds structured prompts for AI attack mode."""

    disable_secator: bool = False

    def build_system_prompt(self) -> str:
        """Build the system prompt with role and action schemas."""
        from secator.tasks.ai_prompts import get_system_prompt
        return get_system_prompt("attack")

    def build_user_prompt(self, targets: List[str], instructions: str = "") -> str:
        """Build the user prompt with targets and instructions."""
        targets_list = "\n".join(f"- {t}" for t in targets)
        return USER_PROMPT_TEMPLATE.format(
            targets_list=targets_list,
            instructions=instructions or "Conduct thorough security testing."
        )

    def build_loop_query(self, iteration: int, max_iterations: int) -> str:
        """Build the current loop query."""
        return LOOP_QUERY_TEMPLATE.format(
            iteration=iteration,
            max_iterations=max_iterations
        )

    def build_full_prompt(
        self,
        targets: List[str],
        instructions: str,
        history: ChatHistory,
        iteration: int,
        max_iterations: int,
    ) -> Dict[str, Any]:
        """Build the complete prompt structure.

        Returns:
            Dict with keys: system, user, history, query
        """
        return {
            "system": self.build_system_prompt(),
            "user": self.build_user_prompt(targets, instructions),
            "history": history.to_messages(),
            "query": self.build_loop_query(iteration, max_iterations),
        }

    def encrypt_prompt(self, prompt: Dict, encryptor) -> Dict:
        """Encrypt sensitive fields in the prompt.

        Args:
            prompt: Full prompt dict with system, user, history, query
            encryptor: SensitiveDataEncryptor instance

        Returns:
            Encrypted prompt dict
        """
        encrypted = prompt.copy()

        # System prompt doesn't contain sensitive data - skip
        # User prompt has targets/instructions - encrypt
        encrypted["user"] = encryptor.encrypt(prompt["user"])

        # Query has iteration info - encrypt
        encrypted["query"] = encryptor.encrypt(prompt["query"])

        # History has all conversation - encrypt each message content
        encrypted["history"] = []
        for msg in prompt["history"]:
            encrypted["history"].append({
                "role": msg["role"],
                "content": encryptor.encrypt(msg["content"])
            })

        return encrypted

    def format_prompt_for_llm(self, prompt: Dict) -> str:
        """Format the structured prompt into a single string for LLM.

        Args:
            prompt: Dict with system, user, history, query

        Returns:
            Formatted string prompt
        """
        parts = []

        # System prompt
        parts.append(prompt["system"])
        parts.append("")  # blank line

        # User prompt
        parts.append(prompt["user"])
        parts.append("")

        # History (if any)
        if prompt["history"]:
            parts.append("## Chat History")
            parts.append("")
            for msg in prompt["history"]:
                role = msg["role"].upper()
                content = msg["content"]
                parts.append(f"**{role}:**")
                parts.append(content)
                parts.append("")

        # Current query
        parts.append("## Current Task")
        parts.append(prompt["query"])

        return "\n".join(parts)

    def format_iteration_for_debug(self, prompt: Dict) -> str:
        """Format just the iteration content (history + query) for debugging.

        Args:
            prompt: Dict with system, user, history, query

        Returns:
            Formatted string with only history and current query
        """
        parts = []

        # History (if any)
        if prompt["history"]:
            parts.append("## Chat History")
            for msg in prompt["history"]:
                role = msg["role"].upper()
                content = msg["content"]
                parts.append(f"**{role}:** {content[:500]}..." if len(content) > 500 else f"**{role}:** {content}")

        # Current query
        parts.append("")
        parts.append("## Current Task")
        parts.append(prompt["query"])

        return "\n".join(parts)
