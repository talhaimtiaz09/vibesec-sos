# Writing findings people can trust

## Labels: every claim gets one

| Label | Use when |
|---|---|
| **Verified** | A human looked at the underlying evidence and accepted it. Say who and when |
| **AI-analyzed** | Claude derived it from evidence; no human has checked it yet |
| **Assumption** | Plausible, not established |
| **Unknown** | The evidence can't answer it (yet) |
| **Disputed** | Evidence conflicts, or someone challenged it |

These do **not** make something Verified: a matching log line, a script's output, several AI answers agreeing,
or the user having read your explanation. Only the user saying "I checked it and accept it" does.

## Traps

- A request that **succeeded** (HTTP 200) doesn't prove data was **read** or what data.
- A row **existing** doesn't prove the attacker **saw** it.
- **No log line ≠ didn't happen.** Logs expire, get sampled, or were never on.
- **Same IP ≠ same person.** VPNs, mobile carriers and cloud providers share IPs. Combine IP + user agent + account + timing.
- **Times:** most logs are UTC. Convert to the incident's timezone and keep the original next to the quote.
  Order events across sources by comparing in UTC.
- Separate when something **happened** from when it was **logged** or **found**.
- Never invent file names, line numbers, counts or timestamps. If you can't read a file, say so.

## Format for each finding (in FINDINGS.md)

1. **What we found:** one sentence.
2. **Proof:** evidence file, line numbers, request/event IDs.
3. **What the evidence says:** a short excerpt or the relevant fields, with secrets and personal data redacted.
4. **What it means:** plain English.
5. **What it doesn't prove:** limits and other explanations.
6. **Status:** label (and who verified, when).
7. **Next check:** what the user should look at to confirm.

Then log one line: `sos.py log -t FINDING --by Claude "F3: attacker created an admin account at 14:02 (AI-analyzed)"`.

## Redaction

- Secrets: first 4 characters only (`sk_l…`).
- Customer emails/names in anything meant to be shared: use labels (Customer1, Customer2) and keep the key separately.
- Session tokens: first 6 characters at most.
