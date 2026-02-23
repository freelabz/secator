"""Prompt builder for AI attack mode."""
from dataclasses import dataclass
from typing import Dict, List

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
        from secator.tasks.ai import get_system_prompt
        return get_system_prompt("attack", disable_secator=self.disable_secator)

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
    ) -> Dict[str, any]:
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
