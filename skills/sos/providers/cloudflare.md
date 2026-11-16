# Cloudflare (Pages, Workers, DNS, WAF, KV/D1/R2)

## What disappears first

| # | Source | Kept for (check your plan) | How to save it |
|---|---|---|---|
| 1 | **Workers / Pages Functions logs** | **Live only** unless Workers Logs (observability) is on; then a few days | Dashboard → Workers → your worker → **Logs**: query the window, export. `wrangler tail` is live only |
| 2 | **Security events** (WAF, blocks, challenges) | As little as a day or so on lower plans | Dashboard → Security → **Events**: filter the window, export / screenshot top IPs, paths, user agents |
| 3 | **HTTP traffic analytics** (sampled) | Days to weeks | Dashboard → Analytics, or the GraphQL Analytics API (read-only query) |
| 4 | **Account audit log** (who changed settings, tokens, rules) | ~18 months | Dashboard → Manage account → **Audit log**, export |
| 5 | **KV / D1 / R2 data** | Changes live | `wrangler d1 export`, `wrangler kv key list` (below) |

## Stop the bleeding (reversible)

- **Block traffic:** Security → WAF → custom rule (block IP, ASN, country, path). Or turn on **Under Attack Mode**.
- **Important:** WAF rules only protect your **custom domain**. The `*.workers.dev` / `*.pages.dev` address goes around them.
  Turn off the workers.dev route, or put it behind **Cloudflare Access**.
- **Put the app behind a login quickly:** Zero Trust → Access → add an application with an allow-list policy.
- **Leaked API token:** My Profile → API Tokens → roll or revoke. Check the audit log for what it did.
- **Leaked secret in a Worker:** rotate at the provider, then `wrangler secret put` (it will ask) and redeploy.

## Save the evidence

```bash
wrangler whoami
wrangler deployments list                      # which version was live when
wrangler d1 export <db> --remote --output .vibesec-sos/incidents/<id>/incoming/d1.sql
wrangler kv key list --namespace-id <id> --remote > .vibesec-sos/incidents/<id>/incoming/kv-keys.json
python3 "$VIBESEC_SOS" save d1-export .vibesec-sos/incidents/<id>/incoming/d1.sql
```

GraphQL Analytics (`POST https://api.cloudflare.com/client/v4/graphql` with a **query**, never a mutation) is read-only.
Use a **read-only API token** in an env var: `-H "Authorization: Bearer $CF_API_TOKEN"`.

## What to look for

- Requests from VPN/cloud ranges with scripting user agents (`python-httpx`, `curl`, `Go-http-client`) hitting auth or admin routes
- Many requests to one path with increasing IDs (someone walking through records)
- Audit log: new API tokens, DNS changes, WAF rules disabled, new members
- Workers logs: errors or auth failures right before the first successful attacker request

Many real users share VPN IP ranges (e.g. WARP, iCloud Private Relay). Match IP **and** user agent **and** account before calling something attacker traffic.

## Don't

- Don't delete the Worker, Pages project or KV namespace. Roll back or block instead.
- Don't trust that a missing log line means nothing happened; logs are sampled or short-lived.
