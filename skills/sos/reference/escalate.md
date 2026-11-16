# When and who to escalate to

Not legal advice. Laws differ by country and industry. When in doubt, ask a lawyer early: deadlines can be short.

## Get professional help when

- Personal data (emails, names, addresses, IDs), financial, health or children's data was likely exposed
- Payment card data is involved
- There's a ransom or extortion demand
- The attacker still has access and you can't remove it
- You don't control the account any more
- You're regulated (finance, health, government contracts) or a customer contract requires it

## Who

| Who | When | What to send |
|---|---|---|
| **Your cloud/host provider** (AWS, Google Cloud, Vercel, Supabase, Cloudflare, Firebase) | Abuse on their platform, fraudulent charges, account takeover | Account/project ID, time window, what you saw. Most have a security or abuse contact |
| **An incident response firm** | Anything on the list above. Your cyber insurance (if any) may assign one: **call the insurer first**, some policies require it | `HANDOFF.md` + evidence list with fingerprints |
| **A lawyer / your data protection officer** | Personal data exposed; notification decisions | `HANDOFF.md` |
| **Data protection regulator** | Often required for personal data breaches (e.g. GDPR: within **72 hours** of becoming aware) | Through your lawyer/DPO |
| **Affected users/customers** | When their data or accounts were involved, or required by law/contract | Plain, honest note: what happened, what data, what you did, what they should do |
| **Law enforcement** | Extortion, fraud, significant theft | Your country's cybercrime reporting service |

## Don't

- Don't pay a ransom or negotiate on your own.
- Don't publicly name a suspected attacker.
- Don't tell customers "no data was accessed" unless the evidence actually shows it, and remember missing logs don't prove absence.
