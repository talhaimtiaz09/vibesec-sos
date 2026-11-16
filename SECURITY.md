# Security policy

Found a way to bypass a guardrail (a destructive command that isn't blocked, or a way evidence can be silently changed),
or a problem in the guidance that could make an incident worse? Please open a
[private security advisory](https://github.com/talhaimtiaz09/vibesec-sos/security/advisories/new) rather than a public issue.

The hooks are a guardrail, not a sandbox: an approved command still runs with your permissions. Bypasses that need the
user to approve a clearly destructive action are expected behaviour, but improvements to the warnings are welcome.
