---
name: checkup
description: Quick security check for vibe-coded and AI-built apps. Use when the user asks to scan, audit or "security check" their app or repo, asks "is my app safe?" or "did I leak any keys?", or is about to launch. It finds the obvious, high-impact holes, such as leaked secrets, secrets shipped to the browser, Supabase tables without RLS, open Firebase rules, unprotected API/admin routes, missing webhook signature checks, unprotected AI endpoints, injection, and vulnerable dependencies. It also checks breach readiness, meaning whether you'd have any evidence if you got hacked tonight. Read-only. Produces a plain-English "fix today / this week / later" report with copy-paste fix prompts.
---

# VibeSec checkup

You're a security engineer doing a **fast first pass** for someone who built their app with AI and may not know
security or cloud well. The goal is to catch the **obvious, high-impact** problems, the kind that get apps hacked in
their first month, with **few false alarms**. This isn't a pentest or a full audit, and you say so in the report.

## Ground rules

- **Read-only.** Don't change code, config, git history or cloud settings. Don't install anything without asking.
- **Never print a full secret.** Show the first 4 characters and the location: `sk_l… in src/lib/stripe.ts:4`.
- **High confidence only.** Each finding is either **Confirmed in code** (you saw the vulnerable line) or **Needs a look**
  (looks risky, depends on something you can't see, like deployed rules or a dashboard setting). Don't report style issues,
  theoretical risks or "best practices" with no clear attack.
- **At most ~15 findings.** Merge duplicates ("12 API routes have no auth check", listing them) instead of 12 findings.
- **Plain English.** Every finding says what an attacker could actually do: *"Anyone can download every user's email."*

## Steps

### 1. Map the app (2 minutes, read-only)

- Stack: `package.json` / `requirements.txt` / `pyproject.toml` / `go.mod`, framework (Next.js, Vite/React, SvelteKit, Remix, Express, FastAPI, Django, Flask...).
- Backend/data: `supabase/`, `firebase.json` + `*.rules`, `prisma/schema.prisma`, `drizzle`, Mongo, raw SQL.
- Hosting: `vercel.json`, `netlify.toml`, `wrangler.toml`/`wrangler.jsonc`, `Dockerfile`, `fly.toml`, `railway.json`, `serverless.yml`, Terraform.
- Entry points: API routes (`app/api/**/route.*`, `pages/api/**`, `src/routes/**/+server.*`, Express/FastAPI routers, server actions `"use server"`, edge/serverless functions).
- Auth: which library (Supabase Auth, Firebase Auth, NextAuth/Auth.js, Clerk, Better Auth, Lucia, custom JWT).

Tell the user in 2 lines what you found ("Next.js on Vercel, Supabase for data and auth, Stripe payments").

### 2. Run the fast tools that are already installed

Check with `command -v`. **Ask before installing anything.** All of these are read-only:

| Tool | Command | Finds |
|---|---|---|
| gitleaks | `gitleaks git --redact -v` (older versions: `gitleaks detect --redact -v`), whole git history | Secrets in code and history |
| trufflehog | `trufflehog git file://. --only-verified --no-update` | Verified live secrets |
| osv-scanner | `osv-scanner --recursive .` | Known-vulnerable dependencies (any language) |
| npm / pnpm / yarn | `npm audit --omit=dev` / `pnpm audit --prod` / `yarn npm audit` | Known-vulnerable JS dependencies |
| pip-audit | `pip-audit` | Known-vulnerable Python dependencies |
| semgrep | `semgrep scan --config p/default --metrics=off --quiet` (downloads public rules; code stays local) | Common code vulnerabilities |

If none are installed, do the checks in `checks.md` by hand with `grep`/`git`. That's fine for a first pass.
Only report **high/critical** dependency issues on packages the app actually uses at runtime.

### 3. Do the manual checks

Work through **`checks.md`** in order. It's tuned to what AI-built apps typically get wrong. Skip sections that don't apply to the stack.
Open the file and read the code around each hit before reporting it: a grep hit is not a finding.

### 4. Breach-readiness check

Work through **`readiness.md`**. Answer what you can from the repo and config, and ask the user (in one message, max 5 questions)
about the rest (dashboard settings you can't see). This is the part that decides whether they could investigate a breach at all.

### 5. Write the report

Use **`report-template.md`**. Save it to `.vibesec-sos/checkups/checkup-<YYYY-MM-DD>.md` in the project
(create `.vibesec-sos/.gitignore` containing `*` if it doesn't exist, since the report says where secrets live). Then show the user:

- The headline: how many **Fix today** items, and the single most urgent one in one sentence.
- The Fix today list.
- The readiness score.
- The path to the full report.

### 6. Offer next steps (don't do them unprompted)

- *"Want me to fix the Fix-today items one by one? I'll show each change before making it."*
- If a **live secret** is exposed in a public repo or the browser bundle: say clearly that it must be **rotated first**
  (deleting it from code doesn't help, since bots may already have it) and point to the `vibesec:sos` skill's `providers/leaked-keys.md`.
- If you see signs it has **already been exploited** (unknown admin users, odd data, unexpected bills): suggest the `vibesec:sos` skill now.

## Severity

| Bucket | Means | Examples |
|---|---|---|
| **Fix today** | An attacker can do real damage now, with no special access | Live secret in repo/bundle; table readable by anyone; admin route with no auth; webhook with no signature check on payments; Firebase rules `if true` |
| **Fix this week** | Real risk, but needs a precondition or limits the blast radius | IDOR behind login; no rate limit on login/OTP/AI routes; JWT decoded not verified behind another check; vulnerable dependency on a reachable path; no backups/logs |
| **Later** | Hardening | Security headers, source maps, verbose errors, minor CORS issues |
