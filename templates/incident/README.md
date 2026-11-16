# Incident: {{NAME}}

Opened {{STARTED}}. ID `{{ID}}`.

This folder is the record of what happened and what you did about it. Keep it. You may need it for your
customers, your cloud provider, a security professional, an insurer or a lawyer.

## What goes where

| File / folder | What it holds | Who writes it |
|---|---|---|
| `ACTION-LOG.md` | Everything **you** did, saw or decided, timestamped. Append-only | Automatic + `sos.py log` |
| `TIMELINE.md` | What the **attacker** did, rebuilt from evidence | Claude drafts, you check |
| `FINDINGS.md` | Each conclusion, with its proof and how sure we are | Claude drafts, you accept |
| `DECISIONS.md` | Big calls: who decided, why, what else was considered | You |
| `UPDATES.md` | Status updates drafted for your team/customers | `sos.py update` |
| `HANDOFF.md` | One-page summary for whoever you escalate to | Claude drafts at the end |
| `evidence/raw/` | Saved logs, exports, command output. **Never edit.** | Automatic + `sos.py save` |
| `evidence/MANIFEST.sha256` | A fingerprint of every evidence file | Automatic |
| `incoming/` | Drop zone for files you download from dashboards, before `sos.py save` | You |
| `notes/` | Scratch work | Anyone |

## Rules while this incident is open

1. **Don't delete anything.** Not the attacker's account, not the weird files, not the logs. Disable or block instead.
2. **Save evidence before you change things.** Logs expire, sometimes within hours.
3. **Every change to a live system is a human decision**, and it gets logged.
4. **No secrets in commands or messages.** Use environment variables.
5. **"Verified" means a human checked it.** Everything else is a lead.

This folder is git-ignored. It can hold customer data and secrets: don't upload it anywhere public.
