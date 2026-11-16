# Breach readiness: "If you got hacked tonight, would you have any evidence?"

Most teams find out during their first incident that the logs they need were never on, or expired last week.
Score one point per **yes**. Answer from the repo/config where you can, and ask the user for the rest (max 5 questions, one message).

| # | Question | Why it matters | How to check / fix |
|---|---|---|---|
| R1 | **Request logs are kept for at least 7 days** | Without them you can't see who called what | Vercel: Log Drain or Observability Plus; Cloudflare: Workers Logs on (`observability.enabled = true` in wrangler config); Supabase: plan retention; GCP: `_Default` is 30 days; AWS: CloudWatch retention set |
| R2 | **Database backups exist and go back at least 7 days** (PITR is better) | Lets you see the data *before* the attack, and recover | Supabase Pro backups / PITR add-on; Firestore PITR + scheduled backups (off by default); Cloud SQL / RDS backups on |
| R3 | **Cloud audit log is on and kept** (who changed settings, keys, access) | Shows how they got in and what they changed | AWS CloudTrail trail (90-day history is free; a trail keeps longer); GCP Admin Activity is always on; Cloudflare/Vercel/GitHub audit logs exist on some plans |
| R4 | **Logins and admin actions are logged by the app itself** | Platform logs rarely show *which user* did *what* | Log sign-ins, failed logins, role changes, deletes and exports with user ID + IP. Never log passwords, tokens or OTP codes |
| R5 | **Spend alerts are set** on cloud and AI providers | A leaked key usually shows up first as a bill | AWS Budgets, GCP budget alerts, OpenAI/Anthropic spend limits, Vercel spend management |
| R6 | **2FA is on** for every account that can deploy or reach data (GitHub, host, cloud, database, domain registrar) | Most takeovers start with a reused password | Each provider's security settings |
| R7 | **Secrets live in the host's env settings / a secret manager**, not in code, and you know which ones exist | You can only rotate what you know about | Keep a list of secret **names** and where each is used (never the values) |
| R8 | **You know who has access** (team members, collaborators, deploy keys, API tokens) and removed old ones | Ex-contractors and forgotten tokens are common ways in | GitHub collaborators + deploy keys, host team members, cloud IAM |

**Scoring in the report:** `Breach readiness: 5/8`, then list the missing ones as "Fix this week" items (R1, R2 and R6 can be "Fix today" if the app holds real user data).

Tell the user the one-line reason for the score: *"If you got hacked tonight, you'd have about 1 hour of request logs and no backups,
so you couldn't tell what was taken."*
