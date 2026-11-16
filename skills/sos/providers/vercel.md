# Vercel

## What disappears first

| # | Source | Kept for (check your plan) | How to save it |
|---|---|---|---|
| 1 | **Runtime / function logs** (requests, `console.log`, errors) | As short as **1 hour** on Hobby, ~1 day on Pro, longer on Enterprise / Observability Plus | Dashboard → project → **Logs**: filter the time window, export/copy. `vercel logs <deployment-url>` streams live logs only |
| 2 | **Firewall / traffic** view | Short, plan-dependent | Dashboard → **Firewall**: screenshot top IPs, paths, countries for the window |
| 3 | **Activity log** (deploys, env var changes, domain changes, team invites) | Long | Dashboard → team → **Activity**: screenshot/export the window |
| 4 | **Deployments** (the exact code that was live) | Kept until deleted | `vercel ls` and `vercel inspect <url>`: note the deployment ID that was live during the attack |

If you have a **Log Drain** (Datadog, Axiom, Better Stack…), your logs are there for longer. Check it first.

## Stop the bleeding (reversible)

- **Block traffic:** Firewall → custom rule to block an IP, country or path. Or turn on **Attack Challenge Mode**.
- **Rotate a leaked secret:** change it at the provider (see `leaked-keys.md`), update it in Settings → Environment Variables.
  Env changes only apply after a redeploy, so **note the current deployment ID first**, then redeploy.
- **Take it offline without deleting:** turn on Deployment Protection (password/Vercel auth) for production, or point the domain to a maintenance page.
- **Old deployments stay reachable** at their own URLs. If an old one has the hole or a leaked secret in its bundle, protect previews with Deployment Protection. Don't delete it: it's evidence.

## Save the evidence (read-only commands)

```bash
vercel whoami
vercel ls --prod                     # deployments: which one was live when
vercel inspect <deployment-url>      # commit, build time, env names
vercel env ls                        # env var NAMES (not values): which secrets exist
git log --since="<date>" --stat      # code changes around the incident
```

`vercel env pull` writes secret values into a local file, so the hook will ask before it runs. Avoid it during an incident.

## What to look for

- Requests to `/api/*` or admin pages from unfamiliar IPs or user agents (`curl`, `python-requests`, `httpx`, `Go-http-client`)
- A spike of 401/403, then a 200 (someone found a way in)
- Secrets with `NEXT_PUBLIC_` in their name: they're in the browser bundle, so anyone can read them
- Env var changes or new team members in the Activity log that nobody on your side made
- A deployment nobody on your team triggered

## Don't

- Don't push a fix straight away: Vercel auto-deploys on push and replaces the live code. Save the deployment ID and logs first.
- Don't delete deployments or projects.
