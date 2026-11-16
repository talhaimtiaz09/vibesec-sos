"""Shared helpers for the VibeSec SOS hooks and CLI. Standard library only."""
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

STATE_DIR = ".vibesec-sos"
ACTIVE_FILE = "active"
PHASES = ["stabilize", "preserve", "investigate", "contain", "recover"]


# --------------------------------------------------------------------------- #
# Locating the project and the open incident
# --------------------------------------------------------------------------- #
def project_dir(start=None):
    """Project root: $CLAUDE_PROJECT_DIR, else the nearest parent holding .vibesec-sos, else start/cwd."""
    env = os.environ.get("CLAUDE_PROJECT_DIR")
    if env:
        return Path(env).resolve()
    here = Path(start or os.getcwd()).resolve()
    for p in [here, *here.parents]:
        if (p / STATE_DIR).is_dir():
            return p
    return here


def active_incident(start=None):
    """Return the open incident folder (Path) or None. Cheap: one stat when nothing is open."""
    marker = project_dir(start) / STATE_DIR / ACTIVE_FILE
    if not marker.is_file():
        return None
    rel = marker.read_text().strip()
    if not rel:
        return None
    inc = (marker.parent / rel).resolve()
    return inc if (inc / "incident.json").is_file() else None


def load_meta(inc):
    try:
        return json.loads((inc / "incident.json").read_text())
    except (OSError, ValueError):
        return {}


def save_meta(inc, meta):
    tmp = inc / "incident.json.tmp"
    tmp.write_text(json.dumps(meta, indent=2) + "\n")
    tmp.replace(inc / "incident.json")


# --------------------------------------------------------------------------- #
# Time: one timezone for everything a human reads
# --------------------------------------------------------------------------- #
def _zone(meta):
    name = (meta or {}).get("timezone")
    if name:
        try:
            from zoneinfo import ZoneInfo
            return ZoneInfo(name)
        except Exception:
            pass
    return datetime.now().astimezone().tzinfo


def now(meta=None):
    return datetime.now(timezone.utc).astimezone(_zone(meta))


def human_ts(meta=None, dt=None):
    """2026-11-16 14:03:22 PKT (UTC+05:00): unambiguous for anyone reading later."""
    dt = dt or now(meta)
    off = dt.strftime("%z")
    off = f"UTC{off[:3]}:{off[3:]}" if off else "UTC"
    return f"{dt.strftime('%Y-%m-%d %H:%M:%S')} {dt.tzname()} ({off})"


def file_ts(meta=None):
    return now(meta).strftime("%Y%m%dT%H%M%S%z")


# --------------------------------------------------------------------------- #
# Evidence and logging
# --------------------------------------------------------------------------- #
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_private(path, data, mode="w"):
    """Create/append a file readable only by the owner (evidence may hold PII and tokens)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | (os.O_APPEND if mode == "a" else os.O_TRUNC), 0o600)
    with os.fdopen(fd, "ab" if isinstance(data, bytes) else "a") as f:
        f.write(data)


def add_to_manifest(inc, evidence_path):
    digest = sha256_file(evidence_path)
    rel = Path(evidence_path).resolve().relative_to(inc.resolve())
    write_private(inc / "evidence" / "MANIFEST.sha256", f"{digest}  {rel}\n", mode="a")
    return digest


def slug(text, limit=40):
    s = re.sub(r"[^A-Za-z0-9]+", "-", text).strip("-").lower()
    return (s[:limit].rstrip("-")) or "item"


def actor(default=None):
    if default:
        return default
    if os.environ.get("VIBESEC_ACTOR"):
        return os.environ["VIBESEC_ACTOR"]
    try:
        import subprocess
        name = subprocess.run(["git", "config", "user.name"], capture_output=True, text=True, timeout=3).stdout.strip()
        if name:
            return name
    except Exception:
        pass
    return os.environ.get("USER", "unknown")


def append_log(inc, tag, message, who=None):
    meta = load_meta(inc)
    line = f"- **{human_ts(meta)}** `{tag.upper()}` ({actor(who)}) {redact(message)}\n"
    write_private(inc / "ACTION-LOG.md", line, mode="a")
    return line


# --------------------------------------------------------------------------- #
# Secret detection and redaction
# --------------------------------------------------------------------------- #
SECRET_PATTERNS = [
    ("private key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ("AWS access key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("GitHub token", r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})"),
    ("Slack token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    ("Stripe secret key", r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}"),
    ("Stripe webhook secret", r"\bwhsec_[A-Za-z0-9]{10,}"),
    ("OpenAI key", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}"),
    ("Anthropic key", r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    ("Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ("SendGrid key", r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"),
    ("JWT", r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    ("bearer token", r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}"),
    ("password in URL", r"[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]{3,}@"),
    ("secret assignment", r"(?i)\b(?:password|passwd|secret|token|api[_-]?key|service[_-]?role[_-]?key|private[_-]?key)\s*[:=]\s*[\"']?(?!\$)[A-Za-z0-9_\-/+=.]{12,}"),
]
_SECRET_RE = [(name, re.compile(p)) for name, p in SECRET_PATTERNS]


def find_secrets(text):
    """Names of secret types found in text (empty list if none)."""
    if not text:
        return []
    return sorted({name for name, rx in _SECRET_RE if rx.search(text)})


def redact(text):
    """Keep the first 4 characters of each match so a human can still tell which key it was."""
    if not text:
        return text
    for _, rx in _SECRET_RE:
        text = rx.sub(lambda m: m.group(0)[:4] + "…[REDACTED]", text)
    return text


def strings_in(obj):
    """Every string inside a JSON-like value, joined (for scanning tool inputs)."""
    out = []

    def walk(v):
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, (list, tuple)):
            for x in v:
                walk(x)

    walk(obj)
    return "\n".join(out)
