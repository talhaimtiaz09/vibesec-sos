# Leaked or abused API keys

## Is it actually secret?

Some keys are **meant to be public** and are not a breach by themselves:

| Public by design | Real secret |
|---|---|
| Firebase web `apiKey` | Firebase/Google **service account JSON** |
| Supabase **anon / publishable** key | Supabase **service_role / secret** key |
| Stripe `pk_live_...` / `pk_test_...` | Stripe `sk_live_...`, `rk_live_...`, `whsec_...` |
| Google Maps browser key (restrict it to your domain) | OpenAI `sk-...`, Anthropic `sk-ant-...`, AWS `AKIA...` + secret |

Public keys still need protection: rules/RLS for Firebase/Supabase, domain restrictions for Google keys.

## The order (a live key is the one exception to "preserve first")

A key that's being abused is **ongoing damage**. Revoking it doesn't delete any logs. So:

1. **Note it:** where it leaked (file, commit, URL, screenshot), when you found it, and the key's **ID or first 4-8 characters**. Never the whole key. `sos.py log -t STABILIZE "..."`
2. **Revoke or rotate it** now (table below). Prefer *disable* if the provider offers it.
3. **Save the usage**: the provider's usage/billing page and request logs for the window. Export or screenshot into `incoming/`, then `sos.py save`.
4. **Replace it** in your app: env var on your host, then redeploy (note the old deployment ID first).
5. **Find how it leaked** and fix that: frontend env prefix (`NEXT_PUBLIC_`, `VITE_`), committed `.env`, logs, an AI chat or screenshot, a public repo or gist.
6. **Check what else it could reach.** An AWS or service-account key can create more keys. See `aws.md` / `gcp.md`.

## Where to revoke

| Key | Revoke / rotate | Check usage |
|---|---|---|
| OpenAI | platform.openai.com → API keys → revoke; set project budget limits | Usage page (filter by project/key) |
| Anthropic | console.anthropic.com → API keys → disable/revoke; set spend limits | Usage / cost pages |
| Stripe secret key | Dashboard → Developers → API keys → **Roll key** (expire the old one now) | Developers → **Logs** (request IP), **Events** |
| Stripe webhook secret | Developers → Webhooks → endpoint → roll secret | Webhook attempts |
| AWS access key | See `aws.md`: set it **Inactive** | CloudTrail by AccessKeyId |
| Google / Firebase service account | See `gcp.md`: **disable** the key | Logging by principal |
| Google API key | Credentials → regenerate, or restrict to domains/APIs | APIs & Services → Metrics |
| Supabase service_role | See `supabase.md` | API logs |
| GitHub token | Settings → Developer settings → tokens → revoke | Security log |
| Email/SMS (SendGrid, Resend, Mailgun, Twilio) | Dashboard → API keys → revoke | Sent/activity log: look for spam or phishing sent to *your* users |
| Database URL with password | Change the DB user's password | DB connection logs |
| Session/JWT secret (`JWT_SECRET`, `NEXTAUTH_SECRET`, `AUTH_SECRET`) | Rotate: logs everyone out | Look for admin sessions you can't explain: a leaked signing secret lets anyone mint any session |

## Stripe extra checks (money can move)

- Payout bank account or schedule changed? (Settings → Payouts). This is urgent: contact Stripe support.
- Unexpected refunds, new connected accounts, customers or payment methods exported in bulk.

## What to tell the user

Plainly: *"Assume this key was used. Rotating it stops new use. Next we check what it was used for."*
Bots scan public GitHub, npm packages and frontend bundles for keys within minutes. Several providers get alerted
by GitHub and may revoke a key automatically and email the owner.
