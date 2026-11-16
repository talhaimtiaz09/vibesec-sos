#!/usr/bin/env python3
"""VibeSec SOS incident CLI. Standard library only.

  sos.py start  [--name "short name"] [--tz Area/City]   open an incident (turns on incident mode)
  sos.py status                                          where things stand
  sos.py log    [-t TAG] [--by NAME] "message"           add an entry to ACTION-LOG.md
  sos.py phase  <stabilize|preserve|investigate|contain|recover>
  sos.py save   <label> <file> [--move]                  add an exported file to evidence (hashed)
  sos.py verify                                          re-check every evidence hash
  sos.py update [--status TEXT]                          draft a status update from the log
  sos.py close  [--reason TEXT]                          close the incident (turns incident mode off)

Tags: STABILIZE PRESERVE INVESTIGATE FINDING DECISION CONTAIN COMMS NOTE (default).
"""
import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "hooks"))

from common import (ACTIVE_FILE, PHASES, STATE_DIR, active_incident, add_to_manifest, append_log, file_ts,  # noqa: E402
                    human_ts, load_meta, now, project_dir, save_meta, sha256_file, slug, write_private)

TEMPLATES = ROOT / "templates" / "incident"
PHASE_HELP = {
    "stabilize": "Stop active damage with reversible moves only (rotate/disable keys, pause, block).",
    "preserve": "Save logs, backups and exports before they expire. Nothing else changes yet.",
    "investigate": "Work out what happened from the saved evidence. Read-only.",
    "contain": "Close the hole and remove attacker access. Every change approved and logged.",
    "recover": "Bring things back, tell the people who need to know, write the handoff.",
}


def die(msg, code=1):
    print(f"sos: {msg}", file=sys.stderr)
    sys.exit(code)


def need_incident():
    inc = active_incident()
    if inc is None:
        die("no open incident in this project. Start one with: sos.py start --name \"what happened\"")
    return inc


# --------------------------------------------------------------------------- #
def cmd_start(a):
    proj = project_dir()
    if active_incident():
        die(f"an incident is already open: {active_incident()}. Close it first, or keep working in it.")
    state = proj / STATE_DIR
    state.mkdir(mode=0o700, exist_ok=True)
    os.chmod(state, 0o700)
    gi = state / ".gitignore"
    if not gi.exists():
        gi.write_text("# Incident evidence can hold customer data and secrets. Never commit it.\n*\n")

    meta = {"timezone": a.tz} if a.tz else {}
    started = now(meta)
    name = a.name or "incident"
    inc_id = f"{started.strftime('%Y%m%d-%H%M')}-{slug(name, 30)}"
    inc = state / "incidents" / inc_id
    for sub in ("evidence/raw", "incoming", "notes"):
        (inc / sub).mkdir(parents=True, exist_ok=True)
    for d in [inc, *[p for p in inc.rglob("*") if p.is_dir()]]:
        os.chmod(d, 0o700)
    for tpl in sorted(TEMPLATES.glob("*.md")):
        text = tpl.read_text().replace("{{NAME}}", name).replace("{{ID}}", inc_id).replace("{{STARTED}}", human_ts(meta, started))
        write_private(inc / tpl.name, text)
    write_private(inc / "evidence" / "MANIFEST.sha256", "")

    meta.update({
        "id": inc_id,
        "name": name,
        "started": human_ts(meta, started),
        "started_utc": started.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "phase": "stabilize",
        "phase_history": [{"phase": "stabilize", "at": human_ts(meta, started)}],
        "updates": 0,
        "log_cutoff": 0,
    })
    save_meta(inc, meta)
    (state / ACTIVE_FILE).write_text(f"incidents/{inc_id}\n")
    append_log(inc, "NOTE", f"Incident opened: {name}. Incident mode ON (guardrails + automatic logging).")
    print(f"Incident opened: {inc}\nPhase: stabilize. {PHASE_HELP['stabilize']}\n"
          f"Times are recorded in {now(meta).tzname()}. Evidence is git-ignored and readable only by you.")


def cmd_status(a):
    inc = active_incident()
    if inc is None:
        print("No open incident. Incident mode is OFF.")
        return
    meta = load_meta(inc)
    log = (inc / "ACTION-LOG.md").read_text().splitlines()
    entries = [l for l in log if l.startswith("- **")]
    ev = [l for l in (inc / "evidence" / "MANIFEST.sha256").read_text().splitlines() if l.strip()]
    print(f"Incident: {meta.get('name')}  ({inc})\nStarted:  {meta.get('started')}\n"
          f"Phase:    {meta.get('phase')}. {PHASE_HELP.get(meta.get('phase'), '')}\n"
          f"Log:      {len(entries)} entries | Evidence: {len(ev)} files hashed | Updates sent: {meta.get('updates', 0)}")
    if entries:
        print("Last entries:")
        for l in entries[-5:]:
            print("  " + l[2:])


def cmd_log(a):
    inc = need_incident()
    line = append_log(inc, a.tag, " ".join(a.message), who=a.by)
    print("logged: " + line.strip()[2:])


def cmd_phase(a):
    inc = need_incident()
    meta = load_meta(inc)
    old = meta.get("phase")
    meta["phase"] = a.phase
    meta.setdefault("phase_history", []).append({"phase": a.phase, "at": human_ts(meta)})
    save_meta(inc, meta)
    append_log(inc, "DECISION", f"Phase {old} → {a.phase}. {PHASE_HELP[a.phase]}", who=a.by)
    print(f"Phase: {a.phase}. {PHASE_HELP[a.phase]}")


def cmd_save(a):
    inc = need_incident()
    src = Path(a.file).expanduser().resolve()
    if not src.is_file():
        die(f"not a file: {src}")
    meta = load_meta(inc)
    dest = inc / "evidence" / "raw" / f"{file_ts(meta)}_{slug(a.label)}{''.join(src.suffixes)[-12:] or '.bin'}"
    before = sha256_file(src)
    shutil.copy2(src, dest)
    os.chmod(dest, 0o600)
    digest = add_to_manifest(inc, dest)
    if digest != before:
        die("hash changed during copy; source is still being written? Try again.")
    if a.move:
        src.unlink()
    append_log(inc, "PRESERVE", f"Saved {a.label}: `{dest.relative_to(inc)}` from `{src}` (sha256 {digest[:12]}…)", who=a.by)
    print(f"saved {dest}\nsha256 {digest}")


def cmd_verify(a):
    inc = need_incident()
    bad = ok = 0
    listed = set()
    for line in (inc / "evidence" / "MANIFEST.sha256").read_text().splitlines():
        if not line.strip():
            continue
        digest, rel = line.split("  ", 1)
        listed.add(rel)
        p = inc / rel
        if not p.is_file():
            print(f"MISSING  {rel}")
            bad += 1
        elif sha256_file(p) != digest:
            print(f"CHANGED  {rel}")
            bad += 1
        else:
            ok += 1
    extra = [str(p.relative_to(inc)) for p in (inc / "evidence").rglob("*") if p.is_file() and p.name != "MANIFEST.sha256"
             and str(p.relative_to(inc)) not in listed]
    for rel in extra:
        print(f"UNHASHED {rel}")
    result = f"{ok} OK, {bad} missing/changed, {len(extra)} unhashed"
    append_log(inc, "PRESERVE", f"Evidence check: {result}", who=a.by)
    print(result)
    sys.exit(1 if bad or extra else 0)


def cmd_update(a):
    inc = need_incident()
    meta = load_meta(inc)
    log = (inc / "ACTION-LOG.md").read_text().splitlines()
    start = meta.get("log_cutoff", 0)
    bullets = []
    for l in log[start:]:
        if l.startswith("- **") and "`CMD`" not in l and "`CHANGE`" not in l:
            # "- **2026-11-16 14:03:22 PKT (UTC+05:00)** `TAG` (who) text" -> "• 14:03 [TAG] text"
            try:
                ts, rest = l[4:].split("** ", 1)
                tag, rest = rest.split(" ", 1)
                text = rest.split(") ", 1)[1] if rest.startswith("(") else rest
                bullets.append(f"• {ts[11:16]} {tag.strip('`')}: {text}")
            except ValueError:
                bullets.append("• " + l[2:])
    n = meta.get("updates", 0) + 1
    draft = (f"*Incident update #{n}* ({human_ts(meta)[11:]})\n*Status:* {a.status or meta.get('phase')}\n"
             f"*Since last update:*\n" + ("\n".join(bullets) or "• No new actions") +
             "\n*Next:* <fill in>\n*Next update by:* <time>")
    write_private(inc / "UPDATES.md", f"\n## Update #{n} ({human_ts(meta)})\n\n```text\n{draft}\n```\n", mode="a")
    meta["updates"] = n
    meta["log_cutoff"] = len(log)
    save_meta(inc, meta)
    print(draft)
    print("\n(Draft saved to UPDATES.md. Fill in Next, check it has no secrets or customer names, then send it yourself.)")


def cmd_close(a):
    inc = need_incident()
    meta = load_meta(inc)
    meta["closed"] = human_ts(meta)
    meta["phase"] = "closed"
    save_meta(inc, meta)
    append_log(inc, "DECISION", f"Incident closed. {a.reason or ''} Incident mode OFF. Files kept in {inc}.".strip(), who=a.by)
    (project_dir() / STATE_DIR / ACTIVE_FILE).unlink()
    print(f"Incident closed. Incident mode is OFF. Everything is still in {inc}.\n"
          "Move the evidence folder somewhere encrypted and access-controlled, and keep it as long as your legal/retention duties require.")


def main():
    p = argparse.ArgumentParser(prog="sos.py", description="VibeSec SOS incident CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("start"); s.add_argument("--name"); s.add_argument("--tz", help="IANA zone, e.g. America/New_York. Default: this computer's zone")
    sub.add_parser("status")
    s = sub.add_parser("log"); s.add_argument("-t", "--tag", default="NOTE"); s.add_argument("--by"); s.add_argument("message", nargs="+")
    s = sub.add_parser("phase"); s.add_argument("phase", choices=PHASES); s.add_argument("--by")
    s = sub.add_parser("save"); s.add_argument("label"); s.add_argument("file"); s.add_argument("--move", action="store_true"); s.add_argument("--by")
    s = sub.add_parser("verify"); s.add_argument("--by")
    s = sub.add_parser("update"); s.add_argument("--status")
    s = sub.add_parser("close"); s.add_argument("--reason"); s.add_argument("--by")

    a = p.parse_args()
    {"start": cmd_start, "status": cmd_status, "log": cmd_log, "phase": cmd_phase, "save": cmd_save,
     "verify": cmd_verify, "update": cmd_update, "close": cmd_close}[a.cmd](a)


if __name__ == "__main__":
    main()
