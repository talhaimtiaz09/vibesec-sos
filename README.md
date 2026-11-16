# VibeSec SOS

**Got hacked? Don't panic. Type `/vibesec:sos`.**

Security check + breach response for vibe-coded apps. A plugin for [Claude Code](https://docs.claude.com/en/docs/claude-code).

```
        BEFORE                                   DURING A BREACH
  ┌───────────────────────┐              ┌──────────────────────────┐
  │  /vibesec:checkup     │              │  /vibesec:sos            │
  │                       │    hacked?   │                          │
  │  • obvious holes      │  ──────────► │  1. stop the damage      │
  │  • fix-today list     │              │  2. save the evidence    │
  │  • breach readiness   │              │  3. find what happened   │
  │                       │              │  4. fix it, safely       │
  └───────────────────────┘              │  5. hand off + report    │
                                         └──────────────────────────┘
```

---

## Why this exists

AI lets anyone ship an app in a weekend. Most of those apps have never had a security review, and most of the people
running them have never handled a breach.

When it happens, the first hour decides most of the outcome, and the natural instincts make it worse:

| Instinct | What it actually does |
|---|---|
| "Delete the attacker's account" | Deletes the record of what they did |
| "Push a fix right now" | Auto-deploy replaces the code they used, before anyone saved it |
| "Restore yesterday's backup" | Overwrites the evidence of what changed |
| "I'll check the logs tomorrow" | Many platforms keep function logs for **1 hour to a few days** |
| "Paste the key so Claude can test it" | The secret is now in your shell history, logs and chat |

VibeSec SOS turns Claude Code into a calm incident responder that knows the right order, and enforces the
dangerous parts with hooks instead of hoping everyone remembers the rules under pressure.

It's built from lessons learned responding to a real production security incident: what had to be preserved first,
what nearly got lost, and which guardrails mattered.

## Install (30 seconds, do it before you need it)

In Claude Code:

```
/plugin marketplace add talhaimtiaz09/vibesec-sos
/plugin install vibesec@vibesec-sos
```

Requires Python 3.10+ (standard library only, nothing else to install).

## Use

### Before: `/vibesec:checkup`

Run it in your project. It reads your code (read-only) and reports the obvious, high-impact holes AI-built apps ship with:

- 🔑 API keys in code, git history or **shipped to the browser** (`NEXT_PUBLIC_…SECRET`)
- 🗄️ Supabase tables without **Row Level Security**, Firebase rules `if true`
- 🚪 API and admin routes with **no auth check**; users reading other users' data
- 🎟️ Tokens decoded but **not verified**
- 💳 Stripe/webhooks without **signature checks**
- 💸 AI/email/SMS endpoints anyone can call (**bill bombs**)
- 💉 SQL injection, `eval`, SSRF, XSS
- 📦 Known-vulnerable dependencies
- 🧯 **Breach readiness:** *if you got hacked tonight, would you have any logs or backups?*

You get a plain-English report: **Fix today / Fix this week / Later**, each with a copy-paste prompt to fix it.

### During: `/vibesec:sos`

Or just say *"I think my app got hacked."* Claude will:

1. **Open an incident.** This creates a private, git-ignored incident folder and turns on **incident mode**.
2. **Ask 3 questions.** What did you notice, where does it run, is it still happening?
3. **Stop the damage, reversibly.** Rotate or disable keys, ban accounts, block IPs. Never delete.
4. **Save the evidence**, shortest-lived first, using a pack for your platform:
   Vercel · Supabase · Firebase · Cloudflare · AWS · Google Cloud · GitHub · leaked API keys (OpenAI, Anthropic, Stripe, …)
5. **Investigate.** One question at a time, with every claim labelled (*Verified* only when **you** checked it).
6. **Fix it** with you, one approved change at a time.
7. **Hand off.** A one-page summary for a security pro, your provider, an insurer or a lawyer, plus status-update drafts.

## What incident mode enforces

While an incident is open, the plugin's hooks run on every action Claude takes:

| | |
|---|---|
| ⛔ **Blocked** | Deleting cloud resources, databases, users, keys or repos · `DROP`/`TRUNCATE`/`DELETE FROM` · force-push / history rewrite · editing or deleting evidence · overwriting the action log · secrets typed into commands or messages |
| ✋ **Asks you first** | Any change to a live system (deploys, key rotation, IAM changes, DB connections, `POST`/`PATCH` requests) · `git push` (it usually triggers a redeploy) · commands that print secrets · editing app code before the investigation is done · sending messages (Slack, Linear, email…) |
| ✅ **Just runs** | Reading logs, listing resources, exporting, dumping the database, snapshots after approval |
| 📝 **Automatic** | Every command is written to `ACTION-LOG.md` with a timestamp in one timezone · output of cloud/DB/HTTP commands is saved to `evidence/` and fingerprinted (SHA-256) · secrets redacted in the log |

New session mid-incident? It re-briefs Claude automatically. When no incident is open, the hooks do nothing.

> **Guardrail, not a sandbox.** The hooks catch the common, costly mistakes, but they can't parse every possible command.
> You are still the one approving changes.

## The incident folder

```
.vibesec-sos/incidents/20261116-1403-leaked-stripe-key/
├── ACTION-LOG.md      what you did, when (append-only, automatic)
├── TIMELINE.md        what the attacker did, rebuilt from evidence
├── FINDINGS.md        each conclusion + proof + how sure we are
├── DECISIONS.md       big calls: who, why, what else was considered
├── UPDATES.md         status updates drafted for your team/customers
├── HANDOFF.md         one page for whoever you escalate to
├── incoming/          drop dashboard exports here
└── evidence/
    ├── raw/           saved logs, exports, command output (never edited)
    └── MANIFEST.sha256
```

Everything stays on your machine. The folder is git-ignored and readable only by you.

CLI (Claude uses it, and you can too):

```bash
python3 "$VIBESEC_SOS" status
python3 "$VIBESEC_SOS" log -t DECISION "Disabled the leaked key instead of deleting it"
python3 "$VIBESEC_SOS" save firewall-events ~/Downloads/events.csv
python3 "$VIBESEC_SOS" verify      # re-check every evidence fingerprint
python3 "$VIBESEC_SOS" update      # draft a status update from the log
python3 "$VIBESEC_SOS" close
```

## What it is not

- Not a penetration test or a full audit. `checkup` is a fast first pass for the obvious holes.
- Not a replacement for a professional incident responder when real customer, payment or health data is involved.
  It tells you when to escalate and prepares the handoff.
- Not legal advice. Breach-notification rules vary (GDPR, for example, gives 72 hours). Talk to a lawyer early.

## Contributing

Provider packs are plain Markdown, so adding Netlify, Railway, Render, Fly.io or Clerk is a great first PR. See [CONTRIBUTING.md](CONTRIBUTING.md).
Guardrail rules live in [`hooks/rules.py`](hooks/rules.py), with tests in [`tests/`](tests/).

## License

[MIT](LICENSE)
