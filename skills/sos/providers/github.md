# GitHub (repos, Actions, secrets)

A secret pushed to a public repo is found by bots within **minutes**. Deleting the commit or making the repo private
does **not** un-leak it. Rotate the secret first, then clean up.

## What disappears first

| # | Source | Kept for | How to save it |
|---|---|---|---|
| 1 | **Actions run logs** | Default 90 days (repo setting) | `gh run list`, `gh run view <id> --log` |
| 2 | **Your account security log** (logins, token creation, SSH keys) | ~90 days | Settings → Security log → export |
| 3 | **Org audit log** | ~180 days (git events shorter, Enterprise only) | Org settings → Audit log → export |
| 4 | **Git history** | Until rewritten | Don't rewrite it. Clone a mirror copy now: `git clone --mirror` |
| 5 | **Secret scanning alerts** | Kept | Security tab → Secret scanning |

## Stop the bleeding (reversible)

- **Leaked secret in a commit:** rotate it at the provider now (see `leaked-keys.md`). Then decide about history.
- **Compromised GitHub account:** change password, check 2FA, Settings → Sessions → revoke. Revoke unknown personal access tokens, SSH keys, OAuth apps and GitHub Apps.
- **Unknown collaborator / deploy key / webhook:** remove access. Note exactly what it was first.
- **Malicious workflow change:** disable the workflow (Actions → workflow → Disable), don't delete the file or runs.

## Save the evidence (read-only)

```bash
gh auth status
git clone --mirror <repo-url> .vibesec-sos/incidents/<id>/incoming/repo-mirror.git
gh api repos/{owner}/{repo}/collaborators --paginate
gh api repos/{owner}/{repo}/keys                 # deploy keys
gh api repos/{owner}/{repo}/hooks                # webhooks
gh api user/keys                                 # your SSH keys
gh secret list
gh run list --limit 200 --json databaseId,event,headBranch,createdAt,conclusion,displayTitle
git log --since="<date>" --all --stat -- .github/workflows package.json package-lock.json pnpm-lock.yaml yarn.lock
```

## What to look for

- Workflow files changed recently, especially `pull_request_target`, or steps that print or send secrets
- Runs triggered by people you don't know; runs on forks
- Lockfile changes adding packages nobody remembers (malicious dependency)
- New collaborators, deploy keys, webhooks pointing to unknown URLs

## Don't

- Don't force-push or rewrite history until you've rotated the secret **and** saved a mirror. (The hook blocks force-push during an incident.)
- Don't delete the repo, runs or workflows.
- Removing history later: use `git filter-repo`, then ask GitHub Support to purge cached views. Rotation is what actually protects you.
