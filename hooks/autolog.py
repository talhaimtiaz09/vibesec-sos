#!/usr/bin/env python3
"""PostToolUse hook: while an incident is open, write every action to ACTION-LOG.md.

- Bash: the command (secrets redacted) is logged. Output of cloud, database and
  HTTP commands is saved under evidence/raw/ and hashed into MANIFEST.sha256.
- Edits to app code are logged as CHANGE.
- MCP calls that send or change something (Slack, Linear, Supabase, ...) are logged.

Nobody has to remember to log: it happens automatically.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import active_incident, add_to_manifest, append_log, file_ts, load_meta, redact, slug, strings_in, write_private  # noqa: E402
import rules  # noqa: E402

CAPTURE = set(rules.CLI_RULES) | set(rules.ALIASES)
MAX_CMD = 600


def _clis(command):
    found = []
    for seg in rules._SPLIT.split(command):
        toks = rules._strip_wrappers(rules._tokens(seg.strip()))
        if toks:
            name = toks[0].rsplit("/", 1)[-1]
            if name in CAPTURE and name != "git":
                found.append((name, toks))
    return found


def _output(resp):
    if isinstance(resp, dict):
        return resp.get("stdout") or "", resp.get("stderr") or "", bool(resp.get("interrupted"))
    return (resp if isinstance(resp, str) else json.dumps(resp)), "", False


def log_bash(incident, tin, resp):
    command = tin.get("command", "")
    if "sos.py" in command:
        return
    meta = load_meta(incident)
    shown = redact(command.strip())
    shown = shown if len(shown) <= MAX_CMD else shown[:MAX_CMD] + " …"
    stdout, stderr, interrupted = _output(resp)
    note = " (interrupted)" if interrupted else ""
    clis = _clis(command)
    if not clis or not (stdout or stderr):
        append_log(incident, "CMD", f"`{shown}`{note}", who="Claude")
        return
    name, toks = clis[0]
    label = slug(" ".join([name] + [t for t in toks[1:] if not t.startswith("-")][:3]))
    base = incident / "evidence" / "raw" / f"{file_ts(meta)}_{label}"
    saved = []
    for suffix, data in ((".out", stdout), (".stderr", stderr)):
        if data:
            path = base.with_name(base.name + suffix)
            write_private(path, data)
            saved.append(f"`{path.relative_to(incident)}` (sha256 {add_to_manifest(incident, path)[:12]}…)")
    append_log(incident, "CMD", f"`{shown}`{note} → saved " + ", ".join(saved), who="Claude")


def log_edit(incident, tool, tin):
    path = tin.get("file_path") or tin.get("notebook_path") or ""
    if not path:
        return
    p = os.path.realpath(path)
    if p.startswith(str(incident.resolve()) + os.sep) or f"{os.sep}.vibesec-sos{os.sep}" in p:
        return
    root = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    rel = os.path.relpath(p, root) if p.startswith(os.path.realpath(root)) else p
    append_log(incident, "CHANGE", f"{tool} `{rel}`", who="Claude")


def log_mcp(incident, tool, tin):
    decision, _ = rules.classify_mcp(tool, tin)
    if decision is None:  # reads are not logged
        return
    text = re.sub(r"\s+", " ", strings_in(tin))[:200]
    append_log(incident, "COMMS" if re.search(r"slack|email|gmail|discord|teams|message|send", tool, re.I) else "CHANGE",
               f"`{tool}`: {text}", who="Claude")


def main():
    try:
        event = json.load(sys.stdin)
    except ValueError:
        return 0
    incident = active_incident(event.get("cwd"))
    if incident is None:
        return 0
    tool = event.get("tool_name", "")
    tin = event.get("tool_input") or {}
    resp = event.get("tool_response", event.get("tool_result"))
    if tool == "Bash":
        log_bash(incident, tin, resp)
    elif tool in ("Edit", "Write", "MultiEdit", "NotebookEdit"):
        log_edit(incident, tool, tin)
    elif tool.startswith("mcp__"):
        log_mcp(incident, tool, tin)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"VibeSec SOS autolog error: {exc}", file=sys.stderr)
        sys.exit(1)  # non-blocking: the action already happened; surface the logging failure
