"""What VibeSec SOS allows, asks about, or blocks while an incident is open.

This is a guardrail, not a sandbox. It catches the common ways people make a
breach worse (deleting things, overwriting evidence, pasting secrets into
commands, redeploying over the live version) and makes every change to a live
system an explicit human decision.

Decisions:
  DENY  - blocked. Deleting is never the first move during an incident.
  ASK   - Claude Code asks the human before running it.
  None  - no opinion; normal Claude Code permissions apply.

Adding a CLI: add an entry to CLI_RULES. Patterns marked "head:" are matched
against the first few non-flag words (e.g. "sql instances delete"); patterns
marked "full:" are matched against the whole command (for flags like --force).
"""
import re
import shlex
from pathlib import Path

from common import find_secrets, strings_in

DENY, ASK = "deny", "ask"
_SEVERITY = {None: 0, ASK: 1, DENY: 2}

# Commands that read or export data are fine (and useful) during an incident.
# Anything else on a cloud CLI changes a live system, so the human decides.
CLI_RULES = {
    "gcloud": {
        "deny": [r"head:.*\b(delete|purge)\b.*", r"head:storage rm.*"],
        "sensitive": [r"head:.*\bprint-(access|identity)-token\b.*", r"head:secrets versions access.*"],
        "read": [r"head:.*\b(list|describe|get-iam-policy|get-ancestors-iam-policy|read|tail|get-value|search-all-resources|search-all-iam-policies|info|version|help)\b.*"],
    },
    "gsutil": {
        "deny": [r"head:(rm|rb)\b.*"],
        "read": [r"head:(ls|du|stat|cat|version|help)\b.*"],
    },
    "aws": {
        "deny": [r"head:\S+ (delete-\S+|terminate-instances|purge-queue|deregister-\S+)\b.*", r"head:s3 (rm|rb)\b.*"],
        "sensitive": [r"head:\S+ (get-secret-value|get-login-password|get-session-token)\b.*", r"full:--with-decryption"],
        "read": [r"head:\S+ (describe-\S+|list-\S+|get-\S+|lookup-events|filter-log-events|tail|head-object)\b.*", r"head:s3 ls\b.*", r"head:sts get-caller-identity.*"],
    },
    "az": {
        "deny": [r"head:.*\b(delete|purge)\b.*"],
        "sensitive": [r"head:.*\bkeys list\b.*", r"head:.*\bsecret show\b.*"],
        "read": [r"head:.*\b(list|show)\b.*"],
    },
    "supabase": {
        "deny": [r"head:(projects delete|db reset|branches delete|functions delete|secrets unset|storage rm)\b.*"],
        "read": [r"head:(projects list|status|inspect|db dump|db diff|migration list|functions list|secrets list|branches list|orgs list|link|logs|help)\b.*", r"full:--version"],
    },
    "vercel": {
        "deny": [r"head:(\S+ )?(rm|remove)\b.*"],
        "sensitive": [r"head:env pull\b.*"],
        "read": [r"head:(ls|list|logs|inspect|whoami|help)\b.*", r"head:(teams|project|projects|domains|dns|certs|env|alias) (ls|list)\b.*", r"full:--version"],
    },
    "firebase": {
        "deny": [r"head:\S*:delete\b.*", r"head:(database:remove|hosting:disable)\b.*"],
        "read": [r"head:\S*:(list|get)\b.*", r"head:(auth:export|use|help|login:list)\b.*", r"full:--version"],
    },
    "wrangler": {
        "deny": [r"head:.*\bdelete\b.*"],
        "read": [r"head:.*\b(tail|whoami|list|status|get|info|export|help)\b.*", r"full:--version"],
    },
    "netlify": {
        "deny": [r"head:(sites:delete|env:unset|unlink)\b.*"],
        "sensitive": [r"head:env:get\b.*"],
        "read": [r"head:(status|sites:list|env:list|logs\S*|help)\b.*", r"full:--version"],
    },
    "fly": {
        "deny": [r"head:.*\b(destroy|delete)\b.*"],
        "read": [r"head:.*\b(status|logs|list|ls|info|releases|history|version|help)\b.*"],
    },
    "railway": {
        "deny": [r"head:(down|delete)\b.*"],
        "sensitive": [r"head:variables\b.*"],
        "read": [r"head:(status|logs|list|whoami|help)\b.*", r"full:--version"],
    },
    "heroku": {
        "deny": [r"head:(apps:destroy|pg:reset|addons:destroy)\b.*"],
        "sensitive": [r"head:config(:get)?\b.*"],
        "read": [r"head:(logs|apps|apps:info|releases|ps|pg:info|access|domains|help)\b.*", r"full:--version"],
    },
    "doctl": {
        "deny": [r"head:.*\bdelete\b.*"],
        "read": [r"head:.*\b(list|get)\b.*"],
    },
    "gh": {
        "deny": [r"head:(repo|release|run|cache|secret|variable) delete\b.*", r"full:(-X|--method)[ =]?DELETE\b"],
        # gh api is a GET unless a method or a body field is given
        "ask": [r"full:(-X|--method)[ =]?(POST|PUT|PATCH)\b", r"full:(^|\s)(-f|-F|--field|--raw-field|--input)(\s|=)"],
        "read": [r"head:api\b.*", r"head:(run|pr|issue|repo|workflow|release|ruleset|gist|label|cache) (list|view|diff|checks|status|watch|download)\b.*",
                 r"head:(secret|variable) list\b.*", r"head:(auth status|search|status|browse|help)\b.*", r"full:--version"],
    },
    "kubectl": {
        "deny": [r"head:(delete|drain)\b.*"],
        "sensitive": [r"head:get (secret|secrets)\b.*"],
        "read": [r"head:(get|describe|logs|top|events|explain|version|cluster-info|api-resources)\b.*", r"head:auth can-i\b.*", r"head:config (view|get-contexts|current-context)\b.*"],
    },
    "terraform": {
        "deny": [r"head:(destroy|force-unlock)\b.*", r"head:state rm\b.*", r"full:\s-destroy\b"],
        "read": [r"head:(plan|show|output|validate|fmt|version|providers|graph)\b.*", r"head:state (list|show|pull)\b.*"],
    },
    "pulumi": {
        "deny": [r"head:(destroy)\b.*", r"head:stack rm\b.*", r"head:state delete\b.*"],
        "sensitive": [r"full:--show-secrets"],
        "read": [r"head:(preview|whoami|about|version|logs)\b.*", r"head:stack (ls|output|history|export)\b.*", r"head:config\s*$"],
    },
    "stripe": {
        "deny": [r"head:.*\bdelete\b.*"],
        "read": [r"head:logs tail\b.*", r"head:\S+ (list|retrieve)\b.*", r"head:(get|help)\b.*", r"full:--version"],
    },
    # Database clients: connecting to a live database is always the human's call.
    "psql": {"deny": [r"full:(?i)\b(drop\s+(table|database|schema|role|user)|truncate\s|delete\s+from)\b"], "read": []},
    "mysql": {"deny": [r"full:(?i)\b(drop\s+(table|database|schema|user)|truncate\s|delete\s+from)\b"], "read": []},
    "mongosh": {"deny": [r"full:(?i)(dropdatabase|\.drop\(|deletemany|deleteone|remove\()"], "read": []},
    "redis-cli": {"deny": [r"full:(?i)\b(flushall|flushdb|del)\b"], "read": []},
    # Dump tools only read from the database: they are how you preserve it.
    "pg_dump": {"read": [r"full:.*"]},
    "pg_dumpall": {"read": [r"full:.*"]},
    "mysqldump": {"read": [r"full:.*"]},
    "mongodump": {"read": [r"full:.*"]},
    # HTTP clients: plain GETs are reads; anything with a body or a method changes something.
    "curl": {"ask": [r"full:(-X|--request)[ =]?['\"]?(POST|PUT|PATCH|DELETE)", r"full:(^|\s)(-d|--data\S*|-F|--form|--json|-T|--upload-file)(\s|=)"], "default": None},
    "wget": {"ask": [r"full:--(post|method|body)\S*"], "default": None},
    "http": {"ask": [r"full:^\s*(POST|PUT|PATCH|DELETE)\b", r"full:\s\S+=\S"], "default": None},
    # git: history is evidence of what was deployed, and a push usually triggers a redeploy.
    "git": {
        "deny": [r"full:\bpush\b.*(\s--force\b|\s--force-with-lease\b|\s-f\b|\s--mirror\b|\s--delete\b|\s:\S)", r"head:(filter-branch|filter-repo)\b.*",
                 r"head:reflog expire\b.*", r"full:\bgc\b.*--prune"],
        "ask": [r"head:push\b.*", r"full:\breset\s+--hard\b", r"full:\bclean\s+-\w*f", r"full:\bbranch\s+-D\b", r"full:\bstash\s+(drop|clear)\b"],
        "default": None,
    },
}
ALIASES = {"flyctl": "fly", "tofu": "terraform", "gcloud.cmd": "gcloud", "mongo": "mongosh", "https": "http", "xh": "http", "mariadb": "mysql"}
WRAPPERS = {"sudo", "env", "time", "nohup", "exec", "command", "npx", "bunx", "pnpx", "dotenv", "doppler", "op", "infisical"}
WRAPPER_PAIRS = {("pnpm", "dlx"), ("pnpm", "exec"), ("yarn", "dlx"), ("bun", "x"), ("npm", "exec")}

REASONS = {
    DENY: "Blocked by VibeSec SOS (incident mode): {what}. Deleting or destroying is never the first move in a breach: it can wipe the evidence of what the attacker did. "
          "Disable or block instead (pause the project, deactivate the key, block the IP). If this really must happen, save the evidence first and have the human run it outside Claude, then log it with `sos.py log`.",
    ASK: "VibeSec SOS (incident mode): {what}. This changes a live system or sends data out. Check: is the evidence already saved? Is there a reversible option? Approve only if yes.",
}

_SPLIT = re.compile(r"\|\||&&|[;|\n`]|\$\(|\(|\)")


def _tokens(segment):
    try:
        return shlex.split(segment, posix=True)
    except ValueError:
        return segment.split()


def _strip_wrappers(tokens):
    while tokens:
        t = tokens[0]
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", t):
            tokens = tokens[1:]
        elif t.rsplit("/", 1)[-1] in WRAPPERS:
            tokens = tokens[1:]
            # skip wrapper flags like `op run --` / `env -i`
            while tokens and (tokens[0].startswith("-") or tokens[0] in {"run"}):
                tokens = tokens[1:]
        elif len(tokens) > 1 and (tokens[0], tokens[1]) in WRAPPER_PAIRS:
            tokens = tokens[2:]
        else:
            break
    return tokens


def _match(patterns, head, full):
    for p in patterns:
        scope, _, rx = p.partition(":")
        target = head if scope == "head" else full
        if re.search(rx if scope == "full" else r"^" + rx + r"$", target):
            return p
    return None


def classify_cli(tokens):
    """(decision, what) for one already-split command."""
    if not tokens:
        return None, ""
    cli = tokens[0].rsplit("/", 1)[-1]
    cli = ALIASES.get(cli, cli)
    rules = CLI_RULES.get(cli)
    if rules is None:
        return None, ""
    args = tokens[1:]
    head = " ".join([a for a in args if not a.startswith("-")][:4])
    full = " ".join(args)
    if _match(rules.get("deny", []), head, full):
        return DENY, f"`{cli} {head}` deletes or destroys something"
    if _match(rules.get("sensitive", []), head, full):
        return ASK, f"`{cli} {head}` prints a secret, which would land in the action log and evidence"
    if _match(rules.get("ask", []), head, full):
        return ASK, f"`{cli} {head}` changes something"
    if _match(rules.get("read", []), head, full):
        return None, ""
    default = rules.get("default", ASK)
    return default, (f"`{cli} {head}` may change a live system" if default else "")


# --------------------------------------------------------------------------- #
# Bash
# --------------------------------------------------------------------------- #
_REDIRECT = re.compile(r"(?<![<>])(>{1,2})\s*([^\s;|&<>]+)")
_ANY_ARG = {"rm", "rmdir", "shred", "unlink", "mv", "truncate", "chmod", "chown", "touch", "tee"}
_LAST_ARG = {"cp", "rsync", "install", "ln", "scp"}


def _targets(segment):
    """Paths a segment writes to or destroys: redirect targets, output flags, and file args of mutating tools."""
    out = [(op, t) for op, t in _REDIRECT.findall(segment)]
    toks = _strip_wrappers(_tokens(segment))
    if not toks:
        return out
    cmd = toks[0].rsplit("/", 1)[-1]
    args = toks[1:]
    files = [a for a in args if not a.startswith("-")]
    if cmd in _ANY_ARG:
        out += [("rm", a) for a in files]
    elif cmd in _LAST_ARG and files:
        out.append(("cp", files[-1]))
    elif cmd == "dd":
        out += [("dd", a[3:]) for a in args if a.startswith("of=")]
    elif cmd in ("sed", "perl") and any(re.fullmatch(r"-\w*i\w*|--in-place\S*", a) for a in args):
        out += [("sed", a) for a in files]
    elif cmd == "find" and ("-delete" in args or "rm" in args):
        out += [("rm", a) for a in files]
    for i, a in enumerate(args):
        if a in ("-o", "--output", "--file", "-f") and i + 1 < len(args):
            out.append(("-o", args[i + 1]))
        elif re.match(r"--(output|file)=", a):
            out.append(("-o", a.split("=", 1)[1]))
    return out


def _is_evidence(path, incident):
    return str(incident / "evidence") in path or re.search(r"(^|[\s'\"=:/])evidence/", path) or path.startswith("evidence/") or "MANIFEST.sha256" in path


def classify_bash(command, incident, phase):
    """Return (decision, reason) for a Bash command while an incident is open."""
    secrets = find_secrets(command)
    if secrets:
        return DENY, ("Blocked by VibeSec SOS: the command contains what looks like a secret (" + ", ".join(secrets) + "). "
                      "Every command is written to the incident action log. Put the value in an environment variable and reference it as $NAME.")
    worst, whats = None, []
    for raw in _SPLIT.split(command):
        seg = raw.strip().strip("{}").strip()
        if not seg:
            continue
        if "sos.py" in seg:  # our own CLI manages evidence and the log
            continue
        targets = _targets(seg)
        if any(_is_evidence(t, incident) for _, t in targets):
            return DENY, ("Blocked by VibeSec SOS: evidence files are append-only and hashed. Don't edit, move, delete or write into evidence/ directly. "
                          "Write the file somewhere else (e.g. the incident's incoming/ folder), then run `sos.py save <label> <file>` to add it with a hash.")
        if any("ACTION-LOG.md" in t and op != ">>" for op, t in targets):
            return DENY, "Blocked by VibeSec SOS: ACTION-LOG.md is append-only. Add entries with `sos.py log`; correct mistakes with a new entry."
        decision, what = classify_cli(_strip_wrappers(_tokens(seg)))
        if decision and _SEVERITY[decision] >= _SEVERITY[worst]:
            if _SEVERITY[decision] > _SEVERITY[worst]:
                whats = []
            worst = decision
            whats.append(what)
    if worst is None:
        return None, ""
    reason = REASONS[worst].format(what="; ".join(dict.fromkeys(whats)))
    if worst == ASK and re.search(r"(^|\s)git\s.*\bpush\b", command):
        reason += " Note: a push usually triggers a new deploy (Vercel, Netlify, Cloudflare Pages), which replaces the version the attacker used."
    return worst, reason


# --------------------------------------------------------------------------- #
# File edits
# --------------------------------------------------------------------------- #
def classify_edit(tool, path, incident, phase):
    if not path:
        return None, ""
    p = Path(path)
    if not p.is_absolute():
        p = Path.cwd() / p
    p = p.resolve()
    inc = incident.resolve()
    if p == inc / "ACTION-LOG.md":
        return DENY, "Blocked by VibeSec SOS: ACTION-LOG.md is append-only. Add entries with `sos.py log`; correct mistakes with a new entry."
    if p == inc / "incident.json":
        return DENY, "Blocked by VibeSec SOS: change the phase with `sos.py phase <name>`, not by editing incident.json."
    if inc / "evidence" in p.parents:
        return DENY, ("Blocked by VibeSec SOS: evidence files are append-only and hashed. Write the file elsewhere (e.g. incoming/), "
                      "then run `sos.py save <label> <file>`.")
    if inc in p.parents or ".vibesec-sos" in p.parts:
        return None, ""
    if phase in ("stabilize", "preserve", "investigate"):
        return ASK, (f"VibeSec SOS (incident mode, phase '{phase}'): this edits app code before the investigation is done. "
                     "The current code is part of the evidence (it's what the attacker used). Approve only for an urgent fix that stops active damage, "
                     "and make sure the current version is committed or saved first.")
    return None, ""


# --------------------------------------------------------------------------- #
# MCP tools (Slack, Linear, GitHub, Supabase, ...)
# --------------------------------------------------------------------------- #
_MCP_DESTROY = re.compile(r"(delete|drop|destroy|purge|remove_project|reset_branch)")
_MCP_CHANGE = re.compile(r"(send|post|create|save|update|comment|reply|publish|upload|share|message|write|draft|schedule|edit|execute|apply|deploy|run|pause|restore|reset|merge|invite|set_|add_|remove)")
_SQL_DESTROY = re.compile(r"(?i)\b(drop\s+(table|database|schema|role|user|policy)|truncate\s|delete\s+from|alter\s+table\s+\S+\s+disable\s+row\s+level\s+security)\b")


def classify_mcp(tool_name, tool_input):
    action = tool_name.split("__", 2)[-1].lower()
    text = strings_in(tool_input)
    if _SQL_DESTROY.search(text):
        return DENY, REASONS[DENY].format(what=f"`{tool_name}` would run destructive SQL")
    if _MCP_DESTROY.search(action):
        return DENY, REASONS[DENY].format(what=f"`{tool_name}` deletes something")
    if not _MCP_CHANGE.search(action):
        return None, ""
    secrets = find_secrets(text)
    if secrets:
        return DENY, ("Blocked by VibeSec SOS: this would send what looks like a secret (" + ", ".join(secrets) + ") outside your machine. "
                      "Remove or redact it (first 4 characters only) and try again.")
    return ASK, (f"VibeSec SOS (incident mode): `{tool_name}` sends or changes something outside your machine. "
                 "Check it has no secrets, customer data or guesses stated as facts.")
