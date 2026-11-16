# Firebase (Firestore, Realtime Database, Storage, Auth, Functions)

Remember: the **`apiKey` in your Firebase web config is not a secret**. It's meant to be public.
What protects your data is **Security Rules**. Rules like `allow read, write: if true;` (or "test mode" that
expired into something open) mean anyone with your project ID can read and write everything.

## What disappears first

| # | Source | Kept for | How to save it |
|---|---|---|---|
| 1 | **Deployed security rules** (and their history) | Kept, but the next deploy replaces them | Console → Firestore/Storage/RTDB → **Rules** tab: screenshot the current rules and the history |
| 2 | **Cloud Functions logs** | ~30 days (Cloud Logging `_Default`) | `gcloud logging read` (see `gcp.md`) |
| 3 | **Current data** | Changes every second | Managed export (below) or Firestore PITR if it was on |
| 4 | **Firestore point-in-time recovery** | Up to 7 days, **only if it was enabled before** | Console → Firestore → Disaster recovery |
| 5 | **Auth users** | In Auth | `firebase auth:export` (below) |

Data Access audit logs (who read which document) are **off by default**, so reads by an attacker usually leave no trace.
Record that as a limit, not as "nothing was read".

## Stop the bleeding (reversible)

- **Rules wide open:** deploy lock-down rules temporarily. Your app will stop working until you fix them properly:
  ```
  rules_version = '2';
  service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read, write: if false; } } }
  ```
  Same idea for Storage and Realtime Database (`".read": false, ".write": false`). The Rules history lets you roll back.
- **Attacker accounts:** Authentication → Users → **Disable account**. Don't delete it.
- **Leaked service-account JSON key:** disable the key (see `gcp.md`). It gives admin access that bypasses rules.
- **Abuse of your API key** (bills, quota): restrict the key to your domains and the APIs you use (Google Cloud console → APIs & Services → Credentials). Turn on **App Check**.

## Save the evidence

```bash
firebase projects:list
firebase auth:export .vibesec-sos/incidents/<id>/incoming/auth-users.json --format=json --project <id>
python3 "$VIBESEC_SOS" save auth-users .vibesec-sos/incidents/<id>/incoming/auth-users.json
# Firestore managed export (needs Blaze plan + a bucket; it's a write, so it will ask):
gcloud firestore export gs://<a-private-bucket>/incident-<date> --project <id>
```

The Auth export includes password hashes. It's sensitive evidence: keep it in the incident folder only.

## What to look for

- Collections with documents you didn't create (`hacked`, ransom notes, spam) or mass changes at one time
- New Auth users around the incident time, especially if your app grants roles via custom claims
- Functions logs showing calls from unknown origins, or errors right before the damage
- Rules history: when did the rules become open, and who deployed them?

## Don't

- Don't "clean up" the vandalised documents yet. Export first.
- Don't delete the project or the database.
