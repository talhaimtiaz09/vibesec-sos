# Checks

Ordered by how often they get AI-built apps hacked. Each check has: **look for** (search starting points), **confirm**
(what must be true before you report it), and **attack** (one sentence for the report).

Search tips: exclude `node_modules`, `.next`, `dist`, `build`, `.git`, `vendor`, `.venv`. Example:
`grep -rInE '<pattern>' --exclude-dir={node_modules,.next,dist,build,.git,vendor,.venv,.vibesec-sos} .`

---

## 1. Secrets in code and git history

**Look for**
- Run gitleaks/trufflehog if available. Otherwise:
  `sk_live_|sk_test_|rk_live_|whsec_|sk-proj-|sk-ant-|AKIA[0-9A-Z]{16}|ghp_|github_pat_|xox[bp]-|-----BEGIN .*PRIVATE KEY|"type": "service_account"|SG\.[A-Za-z0-9_-]{16,}\.|postgres(ql)?://[^:]+:[^@]+@|mongodb(\+srv)?://[^:]+:[^@]+@`
- Committed env files: `git ls-files | grep -E '(^|/)\.env($|\.)' | grep -vE '\.example$|\.sample$|\.template$'`
- Secrets that were committed and later "removed": `git log --all -p -S 'sk_live_' --oneline | head` (repeat for the key types found)
- Hardcoded fallbacks: `process\.env\.[A-Z_]+ \|\| ['"][^'"]{8,}`, `os\.getenv\([^)]+, ['"][^'"]{8,}`

**Confirm:** it's a real key format (not a placeholder like `sk_test_xxx`), and it's a *secret* type (see the
public-by-design table in the sos skill's `providers/leaked-keys.md`). If the repo is public or was ever public, it's **Fix today** even if it was removed.

**Attack:** *"Anyone who has seen this repo can use your <provider> account, and bots scan GitHub for keys within minutes."*

## 2. Secrets shipped to the browser

**Look for**
- Public env prefixes holding secrets: `(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_|NUXT_PUBLIC_)[A-Z0-9_]*(SECRET|PRIVATE|SERVICE_ROLE|SERVICE_KEY|PASSWORD|TOKEN|API_KEY)`
  in `.env*`, code, `next.config.*`, `vite.config.*`. (`NEXT_PUBLIC_SUPABASE_ANON_KEY` and Firebase `apiKey` are fine.)
- Secret-using SDKs imported in client code: files with `"use client"` or under `src/components`, `app/**/page.*` importing
  `stripe` (server SDK), `openai`, `@anthropic-ai/sdk`, `firebase-admin`, `supabase` with `SERVICE_ROLE`, `aws-sdk`.
- `dangerouslyAllowBrowser: true` (OpenAI/Anthropic SDK in the browser).
- Built output, if present: `grep -rlE 'sk_live_|sk-proj-|sk-ant-|service_role' .next/static dist build 2>/dev/null`
- Source maps in production: `productionBrowserSourceMaps: true` (Next.js), `build.sourcemap: true` (Vite). That's **Later** unless it exposes secrets.

**Confirm:** the value really reaches the browser (public prefix, or imported from a client component).

**Attack:** *"Anyone can open your site, press F12, and copy your <provider> key."*

## 3. Supabase: tables without Row Level Security

**Look for**
- In `supabase/migrations/*.sql`: every `create table` in `public` should have a matching `enable row level security`.
  List tables, then list `alter table ... enable row level security`, then diff.
- Policies that allow everyone: `using \(true\)`, `with check \(true\)` on `anon` or `authenticated` for tables holding user data.
- `service_role` key used anywhere outside server-only code.
- `security definer` functions in `public` (callable via `/rest/v1/rpc/`), and views on sensitive tables (views bypass RLS unless `security_invoker`).
- Public storage buckets: `insert into storage.buckets ... public, true` / `public: true`.

**Confirm:** if no migrations are in the repo, mark **Needs a look**, and give the user this to run in the SQL editor:
`select tablename, rowsecurity from pg_tables where schemaname = 'public';`

**Attack:** *"Anyone with your public anon key (which is in your website) can read/change every row in `<table>`."*

## 4. Firebase: open security rules

**Look for** `firestore.rules`, `storage.rules`, `database.rules.json`:
- `allow read, write: if true;` / `allow read: if true;` on anything but truly public data
- `if request.auth != null` on all paths: any signed-up user can read everyone's data
- Test-mode rules: `request.time < timestamp.date(` (open until a date)
- RTDB: `".read": true` / `".write": true` at the root

**Confirm:** rules in the repo may not be what's deployed. If there are no rules files, mark **Needs a look**: Console → Rules tab.

**Attack:** *"Anyone who knows your project ID (it's in your website) can read and overwrite your whole database."*

## 5. API and admin routes with no auth check

**Look for** each server entry point (API routes, server actions, edge functions, Express/FastAPI routes). For each one, is there a
session/user check **before** it reads or changes data? Pay special attention to paths containing `admin`, `internal`, `debug`,
`seed`, `migrate`, `cron`, `export`, `users`, `delete`, `upload`.
- Next.js `middleware.ts` `matcher` that excludes `/api` (routes then need their own checks)
- Server actions (`"use server"`) are public endpoints. Each needs its own auth check.
- Cron routes without a secret header check (`CRON_SECRET`)
- Role checks only in the UI (`{isAdmin && <AdminPanel/>}`) with no check on the server

**Confirm:** read the handler. "Protected by middleware" only counts if the matcher actually covers it.

**Attack:** *"Anyone can call `POST /api/admin/users` directly, with no login."*

## 6. Users can access other users' data (IDOR)

**Look for** handlers that load records by an ID from the request without checking ownership:
- `findUnique({ where: { id: params.id } })`, `findById(req.params.id)`, `.eq('id', id)`, `doc(db, 'orders', id)`,
  `SELECT ... WHERE id = $1` where the ID comes from the URL/body and there's no `userId`/`owner_id` filter or RLS behind it.

**Confirm:** the ID is user-controlled **and** nothing (query filter, RLS, rules) restricts it to the caller.

**Attack:** *"A logged-in user can change the number in `/api/invoices/123` and read anyone's invoice."*

## 7. Broken token checks

**Look for**
- `jwt.decode(` / `jose.decodeJwt(` / `jwtDecode(` used to make auth decisions (decoding **doesn't** check the signature)
- `verify(` with `algorithms: ['none']`, `ignoreExpiration: true`, `verify_signature: False`, `options={"verify_signature": False}`
- Weak or default secrets: `JWT_SECRET=secret|changeme|password|test`, short `AUTH_SECRET`/`NEXTAUTH_SECRET`, secrets hardcoded in code
- "Sign in with Apple/Google" handlers that read the ID token without verifying it against the provider's keys

**Attack:** *"Anyone can make their own token saying they're an admin, and your server will believe it."*

## 8. Webhooks without signature checks

**Look for** webhook routes (`/api/webhooks/*`, `stripe`, `clerk`, `github`, `resend`, `lemonsqueezy`, `paddle`):
- Stripe: must call `stripe.webhooks.constructEvent(rawBody, sig, secret)`. Parsing `req.body` as JSON first breaks it.
- Others: look for the provider's verify call (svix `wh.verify`, HMAC compare).

**Attack:** *"Anyone can send a fake 'payment succeeded' event and get paid features for free."*

## 9. Cost bombs: AI, email and SMS endpoints anyone can call

**Look for** routes that call OpenAI/Anthropic/Gemini/Replicate, send email (Resend, SendGrid, Mailgun) or SMS (Twilio), or send OTPs,
that have **no auth and no rate limit** (`ratelimit`, `upstash`, `express-rate-limit`, `slowapi`, Cloudflare/Vercel rules).

**Attack:** *"Anyone can script this endpoint and run up your AI bill, or use your domain to send spam."*

## 10. Injection

**Look for**
- SQL built with strings: template literals with `${` inside `SELECT|INSERT|UPDATE|DELETE`, `$queryRawUnsafe`, `$executeRawUnsafe`,
  `sql.raw(`, `knex.raw(` with interpolation, Python f-strings in `execute(`
- Code execution: `eval(`, `new Function(`, `child_process.exec(` / `execSync(` with request data, `subprocess(..., shell=True)` with input, `pickle.loads` of input
- Server-side request forgery: `fetch(req.body.url)` / `axios.get(userUrl)` with no allow-list
- XSS: `dangerouslySetInnerHTML`, `v-html`, `{@html` with user content and no sanitizer
- Path traversal: `fs.readFile(path.join(dir, req.query.file))` without normalising and checking the prefix

**Confirm:** the dangerous input really comes from the request.

## 11. File uploads

**Look for** upload handlers: no size limit, no type check, files served back from your own domain (stored XSS via SVG/HTML),
public buckets that allow anonymous writes.

## 12. CORS and cookies

**Look for** `Access-Control-Allow-Origin: *` together with `credentials: true`, or reflecting `req.headers.origin` unchecked on authenticated APIs.
Session cookies without `httpOnly`/`secure`. Usually **Later** unless combined with cookie auth on sensitive routes.

## 13. Secrets and personal data in logs

**Look for** `console.log(` / `logger.*(` / `print(` of `req.body`, `req.headers`, `password`, `token`, `otp`, `code`, `authorization`, `apiKey`, full user objects.

**Attack:** *"Anyone with access to your logs (team members, log tools, an attacker with a leaked token) can read passwords or login codes."*

## 14. Dependencies and supply chain

- Run the audit tool for the stack. Report **high/critical** only, on runtime dependencies, with the fixed version.
- No lockfile committed (installs can pull new, possibly malicious versions).
- GitHub Actions: `pull_request_target` that checks out PR code; secrets echoed in steps; third-party actions on `@main`.

## 15. Debug and admin surfaces left on

`DEBUG = True` (Django), `app.run(debug=True)` (Flask), GraphQL playground/introspection in production, `/api/seed`, `/api/test`,
Swagger/admin panels with no auth, `.git` or `.env` served from `public/`.
