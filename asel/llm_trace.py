# asel/llm_trace.py
"""
Writes human-readable LLM conversation logs for each agent per run.

One file per agent per run:
  asel-runs/<run-id>/llm-build-agent.md
  asel-runs/<run-id>/llm-remediation-agent.md

Each agent.run() call is appended as a new "turn" with its prompt,
all tool calls/results, and the final LLM response.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def _format_tool_calls(messages: list[Any]) -> str:
    """Extract and format tool call/result pairs from a message list."""
    lines: list[str] = []
    for msg in messages:
        role = getattr(msg, "role", None)
        if role == "assistant" and getattr(msg, "tool_calls", None):
            for tc in msg.tool_calls:
                fn = tc.get("function", {})
                name = fn.get("name", "?")
                try:
                    args = json.loads(fn.get("arguments", "{}"))
                    args_str = json.dumps(args, indent=2)
                except Exception:
                    args_str = fn.get("arguments", "")
                lines.append(f"**Tool call:** `{name}`")
                lines.append(f"```json\n{args_str}\n```")
        elif role == "tool":
            result = getattr(msg, "content", "") or ""
            if isinstance(result, list):
                result = " ".join(
                    p.get("text", "") if isinstance(p, dict) else str(p) for p in result
                )
            # Truncate very long tool results in the trace
            if len(result) > 2000:
                result = result[:2000] + "\n[... truncated ...]"
            lines.append(f"**Tool result:** `{getattr(msg, 'tool_name', '?')}`")
            lines.append(f"```\n{result}\n```")
    return "\n".join(lines)


def append_turn(
    log_path: Path,
    *,
    label: str,
    prompt: str,
    run_output: Any,
) -> None:
    """
    Append one agent.run() turn to the log file.

    Parameters
    ----------
    log_path  : path to the .md file (created if missing)
    label     : human label, e.g. "Build stabilization attempt 2" or "Iteration 3 — CVE-2021-44228"
    prompt    : the string passed to agent.run()
    run_output: the RunOutput object returned by agent.run()
    """
    messages = getattr(run_output, "messages", None) or []
    final_response = ""
    if hasattr(run_output, "content") and run_output.content:
        final_response = str(run_output.content)
    else:
        # Fall back: last assistant message that isn't a tool call
        for msg in reversed(messages):
            if getattr(msg, "role", None) == "assistant" and not getattr(msg, "tool_calls", None):
                final_response = msg.get_content_string() if hasattr(msg, "get_content_string") else str(getattr(msg, "content", ""))
                break

    tool_section = _format_tool_calls(messages)

    block = [
        f"## {label}  _{_ts()}_",
        "",
        "### Prompt",
        "```",
        prompt.strip(),
        "```",
        "",
    ]
    if tool_section:
        block += ["### Tool calls", "", tool_section, ""]
    block += [
        "### Response",
        "```",
        final_response.strip() or "(no text response)",
        "```",
        "",
        "---",
        "",
    ]

    with log_path.open("a", encoding="utf-8") as f:
        f.write("\n".join(block) + "\n")


def init_log(log_path: Path, agent_name: str, run_id: str, repo_url: str) -> None:
    """Write the header for a new agent log file."""
    header = "\n".join([
        f"# {agent_name} — LLM Conversation Log",
        f"**Run ID:** {run_id}  ",
        f"**Repo:** {repo_url}  ",
        f"**Started:** {datetime.now(timezone.utc).isoformat()}",
        "",
        "---",
        "",
    ])
    log_path.write_text(header, encoding="utf-8")
