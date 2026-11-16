#!/usr/bin/env python3
"""PreToolUse hook: while an incident is open, block destructive actions and make every live change a human decision.

Does nothing (and costs one stat call) when no incident is open in the project.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import active_incident, load_meta  # noqa: E402
import rules  # noqa: E402


def main():
    try:
        event = json.load(sys.stdin)
    except ValueError:
        return 0
    incident = active_incident(event.get("cwd"))
    if incident is None:
        return 0

    phase = load_meta(incident).get("phase", "stabilize")
    tool = event.get("tool_name", "")
    tin = event.get("tool_input") or {}

    if tool == "Bash":
        decision, reason = rules.classify_bash(tin.get("command", ""), incident, phase)
    elif tool in ("Edit", "Write", "MultiEdit", "NotebookEdit"):
        decision, reason = rules.classify_edit(tool, tin.get("file_path") or tin.get("notebook_path"), incident, phase)
    elif tool.startswith("mcp__"):
        decision, reason = rules.classify_mcp(tool, tin)
    else:
        decision, reason = None, ""

    if decision:
        json.dump({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": reason,
            }
        }, sys.stdout)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # a broken guard must never brick the session; fail towards asking
        json.dump({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                          "permissionDecisionReason": f"VibeSec SOS guard error ({exc}); asking to be safe."}}, sys.stdout)
        sys.exit(0)
