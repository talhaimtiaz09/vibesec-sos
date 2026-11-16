# Supabase

Remember: the **anon / publishable key is public by design**. What protects your data is **Row Level Security (RLS)**.
The **service_role / secret key bypasses RLS**. If it leaked, assume the whole database was readable and writable.

## What disappears first

| # | Source | Kept for (check your plan) | How to save it |
|---|---|---|---|
| 1 | **Logs Explorer**: API/edge requests, Postgres, Auth, Storage, Functions | About **1 day on Free**, ~7 days Pro, longer on Team/Enterprise | Dashboard → **Logs**: pick the source and time window, download results |
| 2 | **Daily backups** | **Free may have none**; Pro ~7 days; PITR is a paid add-on | Dashboard → Database → Backups: note what exists. Take your own dump now (below) |
| 3 | **Current database state** | Changes every second | `supabase db dump` (below) |
| 4 | **Auth audit trail**: `auth.audit_log_entries` table (if enabled), `auth.users` timestamps | In your database | Included in a dump of the `auth` schema |

## Stop the bleeding (reversible)

- **Table readable by anyone?** Turn RLS on: `alter table public.<table> enable row level security;`. With no policies, nobody except the service role can read it. Parts of the app may break; that's expected.
- **service_role / secret key leaked:** create a new secret key and revoke the old one (Project Settings → API Keys). On the older JWT-based keys, rotating the JWT secret **logs every user out and changes the anon key too**. Warn the user first.
- **Attacker user accounts:** Authentication → Users → **ban** or disable them. Don't delete them.
- **DB password leaked:** Database → Settings → reset the password, then update your app's env vars.
- **Restrict who can connect to Postgres:** Database → Network Restrictions (if your plan has it).
- **Pause the project** if it's available and the damage is ongoing.

## Save the evidence

```bash
supabase projects list
supabase link --project-ref <ref>                                   # writes local config only
supabase db dump --linked -f .vibesec-sos/incidents/<id>/incoming/schema.sql
supabase db dump --linked --data-only -f .vibesec-sos/incidents/<id>/incoming/data.sql
supabase db dump --linked --schema auth,storage --data-only -f .vibesec-sos/incidents/<id>/incoming/auth-storage.sql
python3 "$VIBESEC_SOS" save db-dump-public .vibesec-sos/incidents/<id>/incoming/data.sql
```

Dumps contain customer data. They stay in the git-ignored incident folder.

Useful read-only SQL (SQL editor, or `psql` with the human's approval):

```sql
-- Which tables have RLS off?
select schemaname, tablename, rowsecurity from pg_tables where schemaname = 'public' order by rowsecurity, tablename;
-- Policies that let everyone in
select schemaname, tablename, policyname, roles, cmd, qual from pg_policies where qual = 'true' or qual is null;
-- Newest accounts and sign-ins
select id, email, created_at, last_sign_in_at, raw_app_meta_data from auth.users order by created_at desc limit 50;
-- Recent auth events (if the audit table is in use)
select created_at, ip_address, payload->>'action' as action, payload->>'actor_username' as who
from auth.audit_log_entries order by created_at desc limit 200;
```

## What to look for

- API logs hitting `/rest/v1/<table>` with `select=*` from unfamiliar IPs. That's someone reading a whole table through the public key.
- Requests carrying the **service_role** JWT (role `service_role` in the decoded key) from IPs that aren't your servers
- New users with admin-looking metadata, or emails/passwords changed on existing accounts
- Storage objects created or replaced recently (`storage.objects.created_at / updated_at`)
- New database functions, triggers or policies you didn't write (`supabase db diff`)

## Don't

- Don't restore a backup over the live project. Restore into a new project, compare, then decide.
- Don't drop tables or delete users. Disable, ban, revoke.
