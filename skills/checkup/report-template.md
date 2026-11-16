# VibeSec checkup: <project name>

<date> · <stack in one line, e.g. "Next.js on Vercel, Supabase, Stripe">

> A fast first-pass check for the most common, highest-impact holes. It's not a penetration test or a full audit.
> "Confirmed in code" means the vulnerable line was seen. "Needs a look" depends on settings that aren't in the repo.

## Summary

- **Fix today:** <n>. Most urgent: <one sentence>
- **Fix this week:** <n>
- **Later:** <n>
- **Breach readiness:** <x>/8. <one-line reason>

## Fix today

### 1. <Plain title: "Your Stripe secret key is in the public repo">

- **Where:** `<file>:<line>` (secret shown as first 4 characters only)
- **What an attacker can do:** <one sentence>
- **Status:** Confirmed in code / Needs a look
- **Fix:** <2-4 plain steps. For leaked secrets, step 1 is always "rotate the key at <provider>">
- **Prompt for your AI agent:**
  ```text
  <A self-contained prompt they can paste into Claude Code / Cursor to fix exactly this, including the file and what "done" looks like>
  ```

## Fix this week

### <n>. <title>
(same fields)

## Later

- <one line each: title, where, fix>

## Breach readiness (<x>/8)

| # | Check | Status | Fix |
|---|---|---|---|
| R1 | Request logs ≥ 7 days | ✅ / ❌ / ❓ | |
| R2 | DB backups ≥ 7 days | | |
| R3 | Cloud audit log | | |
| R4 | App logs logins + admin actions | | |
| R5 | Spend alerts | | |
| R6 | 2FA everywhere | | |
| R7 | Secrets inventory, none in code | | |
| R8 | Access list reviewed | | |

## What was checked

- Tools run: <gitleaks / osv-scanner / npm audit / none>
- Checks done: <list of checks.md sections covered>
- Not checked: <dashboard settings, deployed rules, infrastructure outside the repo, business logic>

If something here was already exploited (unknown admin users, odd data, unexpected bills), run the `vibesec:sos` skill.
