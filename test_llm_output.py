#!/usr/bin/env python3
"""Test script to show what gets displayed vs what gets sent to the LLM."""

from secator.ai.prompts import format_tool_result
from secator.output_types import Ai

def simulate_shell_action(output: str) -> tuple:
    """Simulate a shell action and show both display and LLM output.

    Returns:
        tuple: (ai_output for display, json for LLM)
    """
    # What gets displayed to user (uses Ai output type's __repr__)
    ai_output = Ai(content=output, ai_type="shell_output")
    display_str = repr(ai_output)

    # What gets sent to the LLM (via format_tool_result)
    action_results = [{"output": output}]
    llm_json = format_tool_result(
        name="shell",
        status="success",
        count=len(action_results),
        results=action_results
    )

    return display_str, llm_json


def main():
    print("=" * 80)
    print("SCENARIO 1: Short output (5 lines)")
    print("=" * 80)

    short_output = "\n".join([f"Line {i}: Some short output" for i in range(1, 6)])
    display, llm = simulate_shell_action(short_output)

    print("\n--- DISPLAY (what user sees) ---")
    print(display)
    print("\n--- LLM JSON (what gets sent to model) ---")
    print(llm)
    print(f"\n--- LLM JSON length: {len(llm)} chars ---")

    print("\n" + "=" * 80)
    print("SCENARIO 2: Long output (50 lines)")
    print("=" * 80)

    long_output = "\n".join([f"Line {i}: {'x' * 50} some longer content here" for i in range(1, 51)])
    display, llm = simulate_shell_action(long_output)

    print("\n--- DISPLAY (what user sees, truncated to 10 lines) ---")
    print(display)
    print("\n--- LLM JSON (what gets sent to model) ---")
    print(llm[:500] + "..." if len(llm) > 500 else llm)
    print(f"\n--- LLM JSON length: {len(llm)} chars ---")

    print("\n" + "=" * 80)
    print("SCENARIO 3: Huge output (500 lines)")
    print("=" * 80)

    huge_output = "\n".join([f"Line {i}: {'y' * 100} lots of data here padding" for i in range(1, 501)])
    display, llm = simulate_shell_action(huge_output)

    print("\n--- DISPLAY (what user sees, truncated to 10 lines) ---")
    print(display)
    print("\n--- LLM JSON (what gets sent to model) ---")
    print(llm[:500] + "..." if len(llm) > 500 else llm)
    print(f"\n--- LLM JSON length: {len(llm)} chars (~{len(llm)//4} tokens) ---")

    print("\n" + "=" * 80)
    print("OBSERVATION: Display is truncated but LLM receives FULL output!")
    print("This could blow up context for huge shell outputs.")
    print("=" * 80)


if __name__ == "__main__":
    main()
