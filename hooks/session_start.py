#!/usr/bin/env python3
"""SessionStart hook: expose the sos CLI path, and re-brief Claude if an incident is still open.

Incidents last longer than one session. Without this, a fresh session after a
restart or /clear would forget the rules mid-incident.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from common import active_incident, load_meta  # noqa: E402

CLI = os.path.join(os.path.dirname(HERE), "scripts", "sos.py")


def main():
    try:
        event = json.load(sys.stdin)
    except ValueError:
        event = {}
    env_file = os.environ.get("CLAUDE_ENV_FILE")
    if env_file:
        with open(env_file, "a") as f:
            f.write(f'export VIBESEC_SOS="{CLI}"\n')

    incident = active_incident(event.get("cwd"))
    if incident is None:
        return 0
    meta = load_meta(incident)
    context = (
        f"VibeSec SOS INCIDENT MODE IS ACTIVE in this project.\n"
        f"Incident: {meta.get('name', incident.name)} | phase: {meta.get('phase', 'stabilize')} | folder: {incident}\n"
        f"CLI: python3 \"{CLI}\" (status | log | phase | save | verify | close)\n"
        "Before doing anything else: invoke the `vibesec:sos` skill, read the incident's ACTION-LOG.md tail and FINDINGS.md, "
        "and tell the user where things stand in 3 lines. Rules: never delete; read-only by default; every live change is the human's decision; "
        "label every claim (Verified only when the human accepts it); plain language; one timezone."
    )
    json.dump({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": context}}, sys.stdout)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        sys.exit(0)
