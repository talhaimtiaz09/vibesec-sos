# Any other platform (Railway, Render, Fly.io, Netlify, Heroku, DigitalOcean, a VPS, ...)

Ask these in order, and look them up in the provider's docs (or the dashboard) as you go.

1. **Where are the request/app logs, and how long are they kept?** Save the shortest-lived first.
2. **Is there an audit/activity log** (who deployed, changed env vars, invited members, created tokens)? Export it.
3. **Are there database backups or point-in-time recovery?** How many days back? Take a manual snapshot/dump now.
4. **What keys/tokens exist** for this platform, and which could the attacker have? Rotate/disable, don't delete.
5. **Who has access?** Team members, SSH keys, deploy keys, OAuth apps.
6. **How do I block traffic or take it offline without deleting anything?** (maintenance mode, scale to zero, IP block)
7. **How do I see the exact version that was live?** Note the deployment/release ID before redeploying.

## A VPS / your own server

- Don't reboot or wipe it: memory and running processes are evidence. Disconnect it from the network if you must stop it (security group / firewall), not power off.
- Save: `last`, `who`, `/var/log/auth.log` (or `journalctl -u ssh`), `~/.bash_history` for each user, `crontab -l` for each user,
  `/etc/cron*`, `ps auxf`, `ss -tupan`, `~/.ssh/authorized_keys` for each user, recently changed files (`find / -mtime -3 -type f 2>/dev/null`).
- Then escalate. A compromised server is usually rebuilt from scratch, not cleaned.
