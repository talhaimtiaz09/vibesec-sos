# VibeSec SOS

A Claude Code plugin for security checks and breach response in AI-built applications.

| Command | When | What it does |
|---|---|---|
| `/vibesec:checkup` | Before an incident | Read-only scan for common, high-impact vulnerabilities and a breach-readiness check |
| `/vibesec:sos` | During an incident | Guided response: contain, preserve evidence, investigate, remediate, hand off |

## Background

Applications built quickly with AI assistants often ship without a security review, and their owners often have no
incident response experience. In the first hours of a breach, common reactions destroy the evidence needed to
understand it:

| Action | Consequence |
|---|---|
| Deleting the attacker's account | Removes the record of what the account did |
| Pushing a fix immediately | Auto-deploy replaces the code that was exploited before it is captured |
| Restoring a backup over production | Overwrites the changes the attacker made |
| Delaying log collection | Some platforms retain function logs for as little as one hour |
| Pasting a key into a command | The secret ends up in shell history, logs and transcripts |

This plugin gives Claude Code a structured incident response procedure and enforces the critical rules with hooks.
It is based on lessons from responding to a production security incident.

## Installation

In Claude Code:

```
/plugin marketplace add talhaimtiaz09/vibesec-sos
/plugin install vibesec@vibesec-sos
```

Requires Python 3.10 or later. No other dependencies.

## Usage

### `/vibesec:checkup`

Reads the project (no changes are made) and reports on:

- Secrets in source code, git history, or client-side bundles (for example `NEXT_PUBLIC_*` variables holding secret keys)
- Supabase tables without Row Level Security; permissive Firebase security rules
- API and admin routes without authentication; missing ownership checks (IDOR)
- Tokens that are decoded but not verified
- Webhook handlers without signature verification
- Unauthenticated or unrate-limited endpoints that call paid APIs (LLM, email, SMS)
- SQL injection, code execution, SSRF and XSS patterns
- Dependencies with known vulnerabilities
- Breach readiness: log retention, backups, audit logging, spend alerts, 2FA, access review

Findings are grouped as Fix today, Fix this week, and Later. Each includes the location, impact, and a prompt that can be
given to a coding agent to apply the fix. The report is saved to `.vibesec-sos/checkups/`.

### `/vibesec:sos`

Also triggered by describing an incident (for example, "I think my app was hacked"). The procedure:

1. Opens an incident record and enables incident mode.
2. Asks what was observed, where the application is hosted, and whether the activity is ongoing.
3. Stabilizes with reversible actions only: rotating or disabling keys, suspending accounts, blocking traffic.
4. Preserves evidence in order of retention, using platform-specific guidance for Vercel, Supabase, Firebase,
   Cloudflare, AWS, Google Cloud, GitHub, and leaked API keys (OpenAI, Anthropic, Stripe and others).
5. Investigates one question at a time. Every conclusion is labelled; only the user can mark a finding as verified.
6. Applies fixes as individually approved changes.
7. Produces a handoff summary for a security professional, provider, insurer or legal counsel, and drafts status updates.

## Incident mode

While an incident is open, the plugin's hooks evaluate every tool call:

| Behaviour | Applies to |
|---|---|
| Blocked | Deleting cloud resources, databases, users, keys or repositories; `DROP`, `TRUNCATE`, `DELETE FROM`; force-push and history rewrites; modifying or deleting evidence; overwriting the action log; secrets in command arguments or outgoing messages |
| Requires approval | Changes to live systems (deployments, key rotation, IAM changes, database connections, `POST`/`PUT`/`PATCH` requests); `git push`; commands that print secrets; editing application code before the investigation phase is complete; outgoing messages via MCP tools |
| Allowed | Reading logs, listing resources, exports, database dumps |
| Recorded | Every command is appended to `ACTION-LOG.md` with a timestamp and UTC offset. Output of cloud, database and HTTP commands is saved to `evidence/raw/` and recorded in a SHA-256 manifest. Secrets are redacted from the log |

When a new session starts during an open incident, a hook restores the incident context. When no incident is open, the
hooks take no action.

The hooks are a guardrail, not a sandbox. They cover common destructive patterns but cannot interpret every possible
command. Approved commands run with the user's permissions.

## Incident folder

```
.vibesec-sos/incidents/<id>/
├── ACTION-LOG.md       actions taken, append-only
├── TIMELINE.md         attacker activity reconstructed from evidence
├── FINDINGS.md         conclusions with supporting evidence and status
├── DECISIONS.md        decisions, owners and alternatives considered
├── UPDATES.md          status update drafts
├── HANDOFF.md          summary for escalation
├── incoming/           staging area for exported files
└── evidence/
    ├── raw/            preserved logs, exports and command output
    └── MANIFEST.sha256
```

All data stays local. The folder is excluded from git and readable only by the owner.

The incident CLI is available as `$VIBESEC_SOS`:

```bash
python3 "$VIBESEC_SOS" status
python3 "$VIBESEC_SOS" log -t DECISION "Disabled the leaked key instead of deleting it"
python3 "$VIBESEC_SOS" save firewall-events ~/Downloads/events.csv
python3 "$VIBESEC_SOS" verify      # re-check evidence hashes
python3 "$VIBESEC_SOS" update      # draft a status update from the log
python3 "$VIBESEC_SOS" close
```

## Limitations

- `checkup` is a first-pass review, not a penetration test or a full audit.
- `sos` does not replace a professional incident response team where personal, payment or health data is involved.
  It identifies when to escalate and prepares the handoff.
- Nothing in this project is legal advice. Breach notification requirements vary by jurisdiction (GDPR, for example,
  requires notifying the regulator within 72 hours).

## Contributing

Provider guides are Markdown files in [`skills/sos/providers/`](skills/sos/providers/). Guardrail rules are in
[`hooks/rules.py`](hooks/rules.py) with tests in [`tests/`](tests/). See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
