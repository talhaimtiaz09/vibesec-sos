# Google Cloud (Cloud Run, Cloud SQL, Compute, Firebase backends)

## What disappears first

| # | Source | Kept for | How to save it |
|---|---|---|---|
| 1 | **Cloud SQL Query Insights** | ~7 days | Console → SQL → instance → Query insights: export/screenshot the window |
| 2 | **Cloud SQL backups / point-in-time recovery** | Usually 7 backups / ~7 days | Take an on-demand backup now (asks first). Lets you look at the database *before* the attack later |
| 3 | **`_Default` log bucket**: app logs, Cloud Run requests, Data Access logs | **30 days** | `gcloud logging read` (below) |
| 4 | **Admin Activity audit logs** (`_Required`): who changed IAM, created keys, deployed | **400 days**, always on | `gcloud logging read` (below) |
| 5 | **Data Access audit logs** (who read data) | **Off by default** (except BigQuery) | Note it as a limit |

## Stop the bleeding (reversible)

- **Leaked service-account key:** disable it, don't delete it.
  `gcloud iam service-accounts keys disable <KEY_ID> --iam-account <sa>@<project>.iam.gserviceaccount.com` (asks first)
- **Attacker IAM members:** remove their role bindings (`remove-iam-policy-binding`, asks first). Record the exact binding first.
- **DB password leaked:** `gcloud sql users set-password` (asks first), then update the app.
- **Public endpoints being abused:** Cloud Armor rule, or set the Cloud Run service to require authentication.
- **Bill exploding:** Billing → Budgets & alerts; stop the resources; contact Google Cloud billing support.

## Save the evidence (read-only)

```bash
gcloud config list
gcloud projects get-iam-policy <project> --format=json
gcloud iam service-accounts list --project <project>
gcloud iam service-accounts keys list --iam-account <sa> --format=json
# Admin activity (IAM changes, key creation, deploys) for a window
gcloud logging read 'logName:"cloudaudit.googleapis.com%2Factivity" AND timestamp>="2026-01-01T00:00:00Z"' \
  --project <project> --format=json --limit=10000
# Everything a given principal did
gcloud logging read 'protoPayload.authenticationInfo.principalEmail="<sa-or-user>"' --project <project> --freshness=30d --format=json
# Cloud Run request logs
gcloud logging read 'resource.type="cloud_run_revision" AND httpRequest.status>=200' --project <project> --freshness=7d --format=json
gcloud compute instances list --project <project>
gcloud sql instances list --project <project>
gcloud sql backups list --instance <instance> --project <project>
```

Big outputs: redirect to `incoming/` (`> .vibesec-sos/incidents/<id>/incoming/audit.json`) then `sos.py save`.

On-demand backup (asks first, safe): `gcloud sql backups create --instance <instance> --project <project>`

## What to look for

- `SetIamPolicy`, `CreateServiceAccountKey`, `google.iam.admin.v1.CreateServiceAccount`: persistence
- Deploys (`run.services.replaceService`, `UpdateFunction`) nobody on your team made
- Compute instances in regions you don't use
- Cloud Run requests to admin routes from unknown IPs

## Don't

- Don't delete keys, service accounts, instances, revisions or log buckets.
- Don't restore a Cloud SQL backup onto the live instance. Restore/clone to a **new** instance if you need to compare (separate approval, costs money).
