# Contributing

Thanks for helping people get through their worst day a little better.

## Good first contributions

- **A provider pack** for a platform that's missing (Netlify, Railway, Render, Fly.io, Clerk, Auth0, PlanetScale, Neon, MongoDB Atlas, Upstash…).
  Copy an existing file in `skills/sos/providers/` and keep the same sections:
  1. **What disappears first**: sources ordered by retention, with "check your plan" where limits vary
  2. **Stop the bleeding (reversible)**: disable/rotate/block, never delete
  3. **Save the evidence**: dashboard exports and **read-only** commands
  4. **What to look for**
  5. **Don't**
  Then add it to the table in `skills/sos/SKILL.md`, and its CLI to `hooks/rules.py` if it has one.
- **A checkup check** in `skills/checkup/checks.md`: only for problems that are common in AI-built apps, high impact and
  confirmable from code. Include *look for*, *confirm* and a one-sentence *attack*.
- **Guardrail rules** in `hooks/rules.py`. Add a test case in `tests/test_hooks.py` for every rule.

## Rules for content

- **Plain language.** The reader may not know what IAM is and is probably panicking.
- **Accuracy over completeness.** Retention periods and plan limits change. If you're not sure, say "check your plan"
  rather than quoting a number. Link to the provider's docs where helpful.
- **Never delete** in any recommended step. Disable, revoke, block, pause, snapshot.
- **Read-only first.** Every command that changes something must be clearly marked as such.

## Development

```bash
python3 -m unittest discover -s tests -v
claude plugin validate .
claude --plugin-dir .      # try it locally
```

Standard library only. No dependencies.
