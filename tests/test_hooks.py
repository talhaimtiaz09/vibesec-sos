"""End-to-end tests: run the real hook scripts and CLI against a temporary project."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GUARD = ROOT / "hooks" / "guard.py"
AUTOLOG = ROOT / "hooks" / "autolog.py"
SESSION = ROOT / "hooks" / "session_start.py"
CLI = ROOT / "scripts" / "sos.py"


class Project:
    def __init__(self, test):
        self.tmp = tempfile.TemporaryDirectory()
        test.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.env = {**os.environ, "CLAUDE_PROJECT_DIR": str(self.dir), "VIBESEC_ACTOR": "tester"}

    def sos(self, *args, check=True):
        return subprocess.run([sys.executable, str(CLI), *args], env=self.env, capture_output=True, text=True, check=check, cwd=self.dir)

    def hook(self, script, event):
        event = {"cwd": str(self.dir), **event}
        r = subprocess.run([sys.executable, str(script)], input=json.dumps(event), env=self.env, capture_output=True, text=True, cwd=self.dir)
        return r

    def decide(self, tool, tool_input):
        out = self.hook(GUARD, {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input}).stdout
        return json.loads(out)["hookSpecificOutput"]["permissionDecision"] if out.strip() else None

    def bash(self, command):
        return self.decide("Bash", {"command": command})

    @property
    def incident(self):
        rel = (self.dir / ".vibesec-sos" / "active").read_text().strip()
        return self.dir / ".vibesec-sos" / rel


class NoIncident(unittest.TestCase):
    def test_everything_passes_through(self):
        p = Project(self)
        self.assertIsNone(p.bash("gcloud sql instances delete prod"))
        self.assertIsNone(p.decide("Write", {"file_path": str(p.dir / "app.ts"), "content": "x"}))
        r = p.hook(AUTOLOG, {"tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_response": {"stdout": "a"}})
        self.assertEqual(r.returncode, 0)
        self.assertFalse((p.dir / ".vibesec-sos").exists())


class Guard(unittest.TestCase):
    def setUp(self):
        self.p = Project(self)
        self.p.sos("start", "--name", "test breach", "--tz", "UTC")

    def test_reads_are_allowed(self):
        for cmd in [
            "gcloud logging read 'severity>=ERROR' --project x --freshness=1d --format=json",
            "gcloud sql instances list --project x",
            "aws cloudtrail lookup-events --region us-east-1 --max-results 5",
            "aws s3 ls s3://bucket",
            "aws iam list-users",
            "vercel ls --prod",
            "supabase db dump --linked -f .vibesec-sos/incidents/x/incoming/data.sql",
            "firebase auth:export users.json --project p",
            "wrangler d1 export mydb --remote --output out.sql",
            "kubectl get pods -A",
            "gh run list --limit 20",
            "gh api repos/o/r/hooks",
            "curl -s https://api.example.com/status",
            "pg_dump \"$DATABASE_URL\" -f dump.sql",
            "git log --since=2026-01-01 --stat",
            "grep -c attacker evidence/raw/x.out > notes/count.txt",
            "ls -la && cat README.md | head",
        ]:
            with self.subTest(cmd=cmd):
                self.assertIsNone(self.p.bash(cmd))

    def test_destruction_is_blocked(self):
        for cmd in [
            "gcloud sql instances delete prod --project x",
            "gcloud storage rm -r gs://evidence",
            "aws iam delete-access-key --access-key-id AKIAEXAMPLE --user-name bob",
            "aws ec2 terminate-instances --instance-ids i-123",
            "aws s3 rm s3://bucket --recursive",
            "supabase db reset --linked",
            "vercel rm my-app --yes",
            "firebase firestore:delete --all-collections",
            "wrangler kv key delete --namespace-id x k",
            "kubectl delete ns prod",
            "terraform destroy -auto-approve",
            "gh repo delete o/r --yes",
            "psql \"$DATABASE_URL\" -c 'DROP TABLE users'",
            "git push --force origin main",
            "npx supabase projects delete abc",
            "FOO=1 sudo aws s3 rb s3://b",
        ]:
            with self.subTest(cmd=cmd):
                self.assertEqual(self.p.bash(cmd), "deny")

    def test_live_changes_ask(self):
        for cmd in [
            "aws iam update-access-key --access-key-id AKIAEXAMPLE --status Inactive --user-name bob",
            "gcloud iam service-accounts keys disable k1 --iam-account sa@p.iam.gserviceaccount.com",
            "vercel --prod",
            "firebase deploy --only firestore:rules",
            "psql \"$DATABASE_URL\" -c 'select 1'",
            "curl -X POST https://api.example.com/ban -d id=1",
            "gh api -X PATCH repos/o/r -f private=true",
            "aws secretsmanager get-secret-value --secret-id prod",
            "git push origin main",
            "wrangler secret put STRIPE_KEY",
        ]:
            with self.subTest(cmd=cmd):
                self.assertEqual(self.p.bash(cmd), "ask")

    def test_secrets_on_command_line_blocked(self):
        self.assertEqual(self.p.bash("curl -H 'Authorization: Bearer sk_live_51Habcdefghijklmnopqrstuv' https://api.stripe.com/v1/charges"), "deny")
        self.assertEqual(self.p.bash("export OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz123456"), "deny")
        self.assertIsNone(self.p.bash("curl -H \"Authorization: Bearer $STRIPE_KEY\" https://api.stripe.com/v1/charges"))

    def test_evidence_is_protected(self):
        inc = self.p.incident
        for cmd in [f"rm -rf {inc}/evidence", "rm evidence/raw/x.out", "echo hi > evidence/raw/new.txt",
                    f"sed -i 's/a/b/' {inc}/evidence/raw/x.out", "mv evidence/raw/a evidence/raw/b", "cp foo.json evidence/raw/"]:
            with self.subTest(cmd=cmd):
                self.assertEqual(self.p.bash(cmd), "deny")
        self.assertEqual(self.p.decide("Write", {"file_path": str(inc / "evidence/raw/x.out"), "content": ""}), "deny")
        self.assertEqual(self.p.decide("Edit", {"file_path": str(inc / "ACTION-LOG.md"), "old_string": "a", "new_string": "b"}), "deny")
        self.assertEqual(self.p.bash(f"echo x > {inc}/ACTION-LOG.md"), "deny")
        self.assertIsNone(self.p.decide("Write", {"file_path": str(inc / "FINDINGS.md"), "content": "F1"}))

    def test_app_edits_depend_on_phase(self):
        app = str(self.p.dir / "src" / "app.ts")
        self.assertEqual(self.p.decide("Edit", {"file_path": app, "old_string": "a", "new_string": "b"}), "ask")
        self.p.sos("phase", "contain")
        self.assertIsNone(self.p.decide("Edit", {"file_path": app, "old_string": "a", "new_string": "b"}))

    def test_mcp(self):
        self.assertEqual(self.p.decide("mcp__slack__send_message", {"text": "update: rotated key sk_live_51Habcdefghijklmnopqrstuv"}), "deny")
        self.assertEqual(self.p.decide("mcp__slack__send_message", {"text": "update: key rotated"}), "ask")
        self.assertEqual(self.p.decide("mcp__supabase__execute_sql", {"query": "delete from users where id = 1"}), "deny")
        self.assertEqual(self.p.decide("mcp__supabase__execute_sql", {"query": "select * from auth.users"}), "ask")
        self.assertIsNone(self.p.decide("mcp__linear__list_issues", {"team": "x"}))


class AutologAndCli(unittest.TestCase):
    def setUp(self):
        self.p = Project(self)
        self.p.sos("start", "--name", "test breach", "--tz", "UTC")

    def test_cloud_output_is_saved_and_hashed(self):
        inc = self.p.incident
        self.p.hook(AUTOLOG, {"tool_name": "Bash", "tool_input": {"command": "gcloud logging read 'x' --project p"},
                              "tool_response": {"stdout": "[{\"a\":1}]", "stderr": ""}})
        raw = list((inc / "evidence" / "raw").glob("*_gcloud-logging-read*.out"))
        self.assertEqual(len(raw), 1)
        self.assertEqual(oct(raw[0].stat().st_mode & 0o777), "0o600")
        self.assertIn(raw[0].name, (inc / "evidence" / "MANIFEST.sha256").read_text())
        log = (inc / "ACTION-LOG.md").read_text()
        self.assertIn("`CMD` (Claude) `gcloud logging read 'x' --project p` → saved", log)
        self.assertIn("(UTC+00:00)", log)

    def test_local_commands_logged_not_saved_and_secrets_redacted(self):
        inc = self.p.incident
        self.p.hook(AUTOLOG, {"tool_name": "Bash", "tool_input": {"command": "echo sk_live_51Habcdefghijklmnopqrstuv | wc -c"},
                              "tool_response": {"stdout": "33"}})
        log = (inc / "ACTION-LOG.md").read_text()
        self.assertIn("sk_l…[REDACTED]", log)
        self.assertNotIn("sk_live_51H", log)
        self.assertEqual(list((inc / "evidence" / "raw").iterdir()), [])

    def test_edit_logged_as_change(self):
        self.p.hook(AUTOLOG, {"tool_name": "Edit", "tool_input": {"file_path": str(self.p.dir / "src/route.ts")}})
        self.assertIn("`CHANGE` (Claude) Edit `src/route.ts`", (self.p.incident / "ACTION-LOG.md").read_text())

    def test_save_verify_tamper(self):
        inc = self.p.incident
        export = inc / "incoming" / "firewall.csv"
        export.write_text("ip,path\n1.2.3.4,/admin\n")
        self.p.sos("save", "firewall events", str(export))
        self.assertEqual(self.p.sos("verify").returncode, 0)
        saved = next((inc / "evidence" / "raw").glob("*_firewall-events.csv"))
        os.chmod(saved, 0o600)
        saved.write_text("tampered")
        r = self.p.sos("verify", check=False)
        self.assertEqual(r.returncode, 1)
        self.assertIn("CHANGED", r.stdout)

    def test_update_and_close(self):
        self.p.sos("log", "-t", "STABILIZE", "Rotated the Stripe key")
        draft = self.p.sos("update").stdout
        self.assertIn("STABILIZE: Rotated the Stripe key", draft)
        self.assertIn("Since last update", draft)
        self.assertNotIn("Rotated", self.p.sos("update").stdout.split("Since last update")[1])
        self.p.sos("close", "--reason", "contained")
        self.assertFalse((self.p.dir / ".vibesec-sos" / "active").exists())
        self.assertIsNone(self.p.bash("gcloud sql instances delete prod"))

    def test_session_start_briefs_claude(self):
        env_file = self.p.dir / "env.sh"
        self.p.env["CLAUDE_ENV_FILE"] = str(env_file)
        out = json.loads(self.p.hook(SESSION, {"hook_event_name": "SessionStart"}).stdout)
        self.assertIn("INCIDENT MODE IS ACTIVE", out["hookSpecificOutput"]["additionalContext"])
        self.assertIn("VIBESEC_SOS=", env_file.read_text())

    def test_evidence_folder_is_private_and_ignored(self):
        state = self.p.dir / ".vibesec-sos"
        self.assertEqual((state / ".gitignore").read_text().strip().splitlines()[-1], "*")
        self.assertEqual(oct(state.stat().st_mode & 0o777), "0o700")


if __name__ == "__main__":
    unittest.main()
