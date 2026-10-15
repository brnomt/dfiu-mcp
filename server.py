# server.py — DFIU v2 (MVP). Local stdio server. No network, no LLM.
from __future__ import annotations

import difflib
import fnmatch
import hashlib
import json
import math
import os
import re
import sqlite3
import subprocess
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterator

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

KB_DIR = Path(os.environ.get("FAILURE_KB_DIR", ".dfiu"))
DB = KB_DIR / "kb.sqlite3"
ARTIFACT_DIR = Path(os.environ.get("FAILURE_KB_ARTIFACTS", ".dfiu/artifacts"))
SCHEMA_VERSION = 1
CHANGE_SUMMARY_VERSION = 1
MAX_DEPTH = 4
MAX_NODES = 32
MAX_MATCHES = 5
# A change is "preceded by a preflight" only if one ran for this project within
# this window. Used both to warn when a confirmation arrives with no recent
# preflight, and to scope which preflight rows a later failure marks 'recurred'.
PREFLIGHT_WINDOW_SECONDS = 1800  # 30 minutes
ENTROPY_THRESHOLD = 4.0      # bits/char, candidates at least 20 characters
ENTROPY_MIN_LEN = 20
MAX_CONDITION_VALUE = 200    # per-string cap inside a condition, like the other text fields
CHANGE_TYPES = {"code", "config", "dependency", "schema", "infra", "firmware", "docs", "test"}
SEVERITIES = {"info", "warning", "blocker"}

# Shown to the agent on connect. A guess is not a fact. This is the only guidance
# that travels over MCP, so it must be self-contained and project-agnostic: no
# project name, path, or domain assumption belongs here.
INSTRUCTIONS = (
    "DFIU is a project-agnostic memory of what already failed, so you do not re-try a dead idea. "
    "It never runs your tools, touches your files, or deploys anything; you drive it by calling "
    "its tools at the right moments.\n"
    "GOLDEN RULE: write only what the user has confirmed by actually trying it. Never record a "
    "theory, a plan, or an assumption that a change worked or failed. Wait until the user says it "
    "works or it does not, then record that fact.\n"
    "LOOK BEFORE YOU TOUCH: before any non-trivial change (editing a file with history, a "
    "migration, a dependency bump, a release, a deploy, or any step that is costly to undo), call "
    "preflight_check first with a ChangeSummaryV1 describing the change. If a required field is "
    "missing, the error names the expected keys. preflight_check only reads rules; it never "
    "creates an incident. Treat an alert as 'this approach already failed' and change course.\n"
    "CANONICAL CYCLE: preflight_check (plan) -> record_failure (user confirmed it broke) -> "
    "verify_resolution (user confirmed a fix by exercising the failing path) -> activate_rule "
    "(promote a verified rule) -> compile_artifacts (write the shareable invariants). Each "
    "response carries the next step in a 'next_step' or 'next_tool' field; follow it. "
    "A hypothesis or an operator_review is never a pass.\n"
    "TO LOOK BACK: list_incidents browses the memory by exact id, by keywords, or by key "
    "fields (project, subsystem, status, error_code, condition_hash, tag, since). Use it "
    "when you need to know whether this already failed; use get_incident_details for the "
    "full write-up of one incident.\n"
    "HOOKS: if your client supports hooks, wire a pre-edit or pre-change hook to call preflight_check "
    "and a confirmation hook to call record_failure/verify_resolution. Keep those hooks generic: key "
    "them off the KB's own history (the files and rules it already tracks), never off a hardcoded "
    "project name, tool, or path, so the same setup works on any project."
)
mcp = FastMCP("dfiu", instructions=INSTRUCTIONS)


# ---------- structured errors ----------
class KBError(Exception):
    def __init__(self, code: str, message: str, fields: list[str] | None = None):
        super().__init__(message)
        self.code, self.message, self.fields = code, message, fields or []

    def to_dict(self) -> dict[str, Any]:
        return {"ok": False, "error": {"code": self.code, "message": self.message,
                                       "fields": self.fields}}


def tool_guard(fn):
    """Turn KBError and unexpected failures into the standard error object."""
    import functools

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except KBError as e:
            return e.to_dict()
        except sqlite3.IntegrityError:
            return KBError("conflict", "Integrity violation").to_dict()
        except Exception:  # never return a traceback, path, or SQL
            return KBError("internal", "Error interno").to_dict()
    return wrapper


# ---------- utilities ----------
def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def window_start(t: str, seconds: int) -> str:
    """The ISO timestamp `seconds` before t. Used to bound the preflight window.
    Lexicographic string comparison on these fixed-offset ISO stamps is a valid
    time order, so callers compare created_at >= window_start(now, N)."""
    return (datetime.fromisoformat(t) - timedelta(seconds=seconds)).isoformat(timespec="microseconds")


def had_recent_preflight(c: sqlite3.Connection, project: str, t: str) -> bool:
    row = c.execute(
        "SELECT 1 FROM preflight_log WHERE project=? AND created_at>=? LIMIT 1",
        (project, window_start(t, PREFLIGHT_WINDOW_SECONDS))).fetchone()
    return row is not None


def canonical_json(obj: Any, indent: int | None = None) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, indent=indent,
                      separators=(",", ": ") if indent else (",", ":"))


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def bounded(name: str, value: str, limit: int) -> str:
    if len(value) > limit:
        raise KBError("too_large", f"{name} exceeds {limit} characters", [name])
    return value


# ---------- secrets (scrub before storing and again on the way out) ----------
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)")),
    ("aws_access_key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("openai_like_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")),
    ("auth_header", re.compile(r"(?i)\b(authorization|proxy-authorization)\s*:\s*\S+(\s+\S+)?")),
    ("url_credentials", re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@")),
    ("assignment", re.compile(r"(?i)\b([A-Z0-9_]*(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY)[A-Z0-9_]*)\s*[=:]\s*['\"]?([^\s'\"]{4,})")),
]
CANDIDATE = re.compile(r"[A-Za-z0-9+/=_\-]{%d,}" % ENTROPY_MIN_LEN)
REDACTED = re.compile(r"\[REDACTED:secret:[a-z_]+\]")
# Legitimate technical tokens that never trigger the entropy warning:
# 0x-prefixed hex addresses (4-16 hex digits), standalone git hashes (7-40 hex
# chars), and sha256:/md5: prefixed digests. Real secret patterns above still
# redact; this only silences the low-confidence entropy warning.
TECH_TOKEN_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?i)(?:sha256|md5):[0-9a-fA-F]+"),
    re.compile(r"0x[0-9a-fA-F]{4,16}"),
    re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{7,40}(?![0-9A-Za-z])"),
]


def shannon(s: str) -> float:
    counts = {ch: s.count(ch) for ch in set(s)}
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def _replace_outside_markers(text: str, pat: re.Pattern[str], repl) -> str:
    """Skip text that is already inside a redaction marker."""
    parts: list[str] = []
    last = 0
    for mark in REDACTED.finditer(text):
        parts.append(pat.sub(repl, text[last:mark.start()]))
        parts.append(mark.group(0))
        last = mark.end()
    parts.append(pat.sub(repl, text[last:]))
    return "".join(parts)


def redact(text: str) -> tuple[str, list[str]]:
    """Redact high-confidence matches. Returns (text, kinds found).
    Idempotent: a marker is not scanned again."""
    found: list[str] = []
    for kind, pat in SECRET_PATTERNS:
        def sub(m: re.Match[str], kind: str = kind) -> str:
            found.append(kind)
            if kind == "assignment":
                return f"{m.group(1)}=[REDACTED:secret:assignment]"
            if kind == "auth_header":
                return f"{m.group(1)}: [REDACTED:secret:auth_header]"
            return f"[REDACTED:secret:{kind}]"
        text = _replace_outside_markers(text, pat, sub)
    return text, sorted(set(found))


def low_confidence_candidates(text: str) -> int:
    """Count high-entropy strings that were not redacted. The strings themselves are not returned.
    Allowlisted technical tokens (0x addresses, git hashes, sha256:/md5: digests) are skipped."""
    clean = REDACTED.sub("", text)
    for pat in TECH_TOKEN_PATTERNS:
        clean = pat.sub(" ", clean)
    return sum(1 for m in CANDIDATE.finditer(clean) if shannon(m.group(0)) >= ENTROPY_THRESHOLD)


def scrub(name: str, value: str, limit: int, warnings: list[str]) -> str:
    value, kinds = redact(bounded(name, value, limit))
    for k in kinds:
        warnings.append(f"{name}: redacted {k}")
    if low_confidence_candidates(value):
        warnings.append(f"{name}: high-entropy string, review (not redacted)")
    return value


def sanitize_condition(node: Any, warnings: list[str]) -> Any:
    """Same scrub as every other stored text, applied to every string in a condition.

    A condition is persisted in rules.condition_json and compiled into invariants.json,
    so it must not be the one path that smuggles a secret into the KB or the artifact.
    Values are also capped at MAX_CONDITION_VALUE characters: the grammar bounds depth
    and node count, not the length of a string. Structure is untouched.
    """
    if isinstance(node, str):
        return scrub("condition", node, MAX_CONDITION_VALUE, warnings)
    if isinstance(node, list):
        return [sanitize_condition(x, warnings) for x in node]
    if isinstance(node, dict):
        return {k: sanitize_condition(v, warnings) for k, v in node.items()}
    return node


# ---------- database ----------
MIGRATIONS: list[str] = [
    # v1
    """
    CREATE TABLE incidents(
      id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
      project TEXT NOT NULL, subsystem TEXT, environment TEXT,
      title TEXT NOT NULL, symptom TEXT NOT NULL, error_code TEXT, condition_hash TEXT,
      root_cause TEXT, resolution TEXT,
      status TEXT NOT NULL CHECK(status IN ('open','change_applied_unverified',
        'verified_resolved','reopened','closed')),
      evidence_summary TEXT, evidence_ref TEXT,
      tags_json TEXT NOT NULL DEFAULT '[]',
      sensitivity TEXT NOT NULL DEFAULT 'normal'
        CHECK(sensitivity IN ('normal','redacted','restricted')));
    CREATE TABLE rules(
      id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
      project TEXT NOT NULL, scope TEXT NOT NULL, title TEXT NOT NULL,
      invariant TEXT NOT NULL CHECK(length(invariant) <= 200 AND instr(invariant, char(10)) = 0),
      condition_json TEXT NOT NULL, action TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('hypothesis','verified','active','stale','deprecated')),
      severity TEXT NOT NULL DEFAULT 'warning' CHECK(severity IN ('info','warning','blocker')),
      confidence REAL NOT NULL DEFAULT 0 CHECK(confidence >= 0 AND confidence <= 1),
      revision INTEGER NOT NULL DEFAULT 1,
      verification_count INTEGER NOT NULL DEFAULT 0,
      last_verified_at TEXT, review_after TEXT, valid_until TEXT,
      stale_reason TEXT, deprecated_at TEXT, deprecation_reason TEXT,
      source_revision TEXT, dependency_paths_json TEXT NOT NULL DEFAULT '[]',
      dependency_fingerprint TEXT, content_hash TEXT NOT NULL,
      UNIQUE(project, content_hash));
    CREATE TABLE incident_rules(
      incident_id TEXT NOT NULL REFERENCES incidents(id),
      rule_id TEXT NOT NULL REFERENCES rules(id),
      created_at TEXT NOT NULL, PRIMARY KEY(incident_id, rule_id));
    CREATE TABLE verification_log(
      id TEXT PRIMARY KEY, incident_id TEXT NOT NULL REFERENCES incidents(id),
      rule_id TEXT REFERENCES rules(id), created_at TEXT NOT NULL,
      verdict TEXT NOT NULL CHECK(verdict IN ('pass','fail','inconclusive')),
      method TEXT NOT NULL CHECK(method IN ('test','reproduction','regression','operator_review')),
      success_criterion TEXT NOT NULL, preconditions_json TEXT NOT NULL,
      exercised_failing_path INTEGER NOT NULL CHECK(exercised_failing_path IN (0,1)),
      environment TEXT, source_revision TEXT, condition_hash TEXT,
      evidence_summary TEXT NOT NULL, evidence_ref TEXT, reviewer TEXT,
      metadata_json TEXT NOT NULL DEFAULT '{}');
    CREATE TABLE rule_transitions(
      id TEXT PRIMARY KEY, rule_id TEXT NOT NULL REFERENCES rules(id),
      from_status TEXT, to_status TEXT NOT NULL, reason TEXT NOT NULL,
      actor TEXT, revision INTEGER NOT NULL, created_at TEXT NOT NULL);
    CREATE TABLE idempotency_keys(
      key TEXT NOT NULL, tool TEXT NOT NULL, request_hash TEXT NOT NULL,
      response_json TEXT NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY(tool, key));
    CREATE TABLE artifact_state(
      name TEXT PRIMARY KEY, sha256 TEXT NOT NULL, rule_count INTEGER NOT NULL,
      written_at TEXT NOT NULL);
    CREATE INDEX idx_incidents_project ON incidents(project, subsystem, created_at DESC);
    CREATE INDEX idx_incidents_status ON incidents(status, created_at DESC);
    CREATE INDEX idx_rules_status ON rules(project, status, scope, id);
    CREATE INDEX idx_vlog_incident ON verification_log(incident_id, created_at DESC);
    CREATE INDEX idx_vlog_rule ON verification_log(rule_id, verdict, created_at DESC);
    CREATE INDEX idx_rt_rule ON rule_transitions(rule_id, created_at);
    """,
    # v2: local preflight log. Stays on this machine.
    """
    CREATE TABLE preflight_log(
      id TEXT PRIMARY KEY,
      project TEXT NOT NULL,
      created_at TEXT NOT NULL,
      status TEXT NOT NULL,
      summary_hash TEXT NOT NULL,
      files_json TEXT NOT NULL,
      rule_ids_json TEXT NOT NULL,
      outcome TEXT NOT NULL DEFAULT 'open' CHECK(outcome IN ('open','recurred')));
    CREATE INDEX idx_preflight_project ON preflight_log(project, created_at DESC);
    """,
    # v3: drop write-only schema. These columns, this table, and this index were
    # written but never read for any decision, and nothing surfaced them. Dropping
    # them removes dead state, not behavior. SQLite >= 3.35 supports DROP COLUMN;
    # the server requires a newer SQLite than that. (rules.confidence stays: it is
    # decremented on a failed re-verification and asserted by the suite.)
    """
    DROP TABLE IF EXISTS artifact_state;
    DROP INDEX IF EXISTS idx_vlog_rule;
    ALTER TABLE rules DROP COLUMN verification_count;
    ALTER TABLE rules DROP COLUMN source_revision;
    ALTER TABLE verification_log DROP COLUMN source_revision;
    ALTER TABLE verification_log DROP COLUMN condition_hash;
    ALTER TABLE verification_log DROP COLUMN metadata_json;
    """,
    # v4: separate the *proposed* fix from the *confirmed* one. Until now the agent's
    # proposed_resolution was written into incidents.resolution, so a confirmed fix
    # had nowhere to land and a guess read back as if it were the resolution. The
    # guess moves to its own columns; resolution/root_cause now hold only what an
    # effective verification confirmed. Existing rows move with the same split.
    """
    ALTER TABLE incidents ADD COLUMN proposed_resolution TEXT;
    ALTER TABLE incidents ADD COLUMN proposed_root_cause TEXT;
    UPDATE incidents SET proposed_resolution=resolution, proposed_root_cause=root_cause;
    UPDATE incidents SET resolution=NULL, root_cause=NULL;
    """,
]


def _open() -> sqlite3.Connection:
    KB_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(KB_DIR, 0o700)
    c = sqlite3.connect(DB, timeout=5, isolation_level=None)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA busy_timeout=5000")
    c.execute("PRAGMA journal_mode=WAL")
    os.chmod(DB, 0o600)
    for suffix in ("-wal", "-shm"):
        extra = Path(str(DB) + suffix)
        if extra.exists():
            os.chmod(extra, 0o600)
    return c


@contextmanager
def tx() -> Iterator[tuple[sqlite3.Connection, str]]:
    """One connection, one IMMEDIATE transaction, one timestamp. Always closes."""
    c = _open()
    try:
        c.execute("BEGIN IMMEDIATE")
        yield c, now()
        c.execute("COMMIT")
    except BaseException:
        c.execute("ROLLBACK")
        raise
    finally:
        c.close()


def migrate() -> None:
    with tx() as (c, _):
        current = c.execute("PRAGMA user_version").fetchone()[0]
        for version in range(current + 1, len(MIGRATIONS) + 1):
            for stmt in MIGRATIONS[version - 1].split(";"):
                if stmt.strip():
                    c.execute(stmt)
            c.execute(f"PRAGMA user_version={version}")


def idempotent(c: sqlite3.Connection, tool: str, key: str, request: dict[str, Any]) -> dict | None:
    if not key:
        return None
    row = c.execute("SELECT request_hash,response_json FROM idempotency_keys WHERE tool=? AND key=?",
                    (tool, key)).fetchone()
    if row is None:
        return None
    if row["request_hash"] != sha256(canonical_json(request)):
        raise KBError("idempotency_conflict", "idempotency_key reused with a different request",
                      ["idempotency_key"])
    return json.loads(row["response_json"])


def remember(c: sqlite3.Connection, tool: str, key: str, request: dict[str, Any],
             response: dict[str, Any], t: str) -> None:
    if key:
        c.execute("INSERT INTO idempotency_keys VALUES(?,?,?,?,?)",
                  (key, tool, sha256(canonical_json(request)), canonical_json(response), t))


# ---------- ChangeSummaryV1 ----------
def norm_path(p: str) -> str:
    pp = PurePosixPath(p.replace("\\", "/"))
    if pp.is_absolute() or ".." in pp.parts:
        raise KBError("invalid_input", f"Path escapes the project: {p}", ["files_touched"])
    s = str(pp)
    return s[2:] if s.startswith("./") else s


def normalize_summary(summary: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Validate a ChangeSummaryV1. Returns (normalized, missing fields)."""
    if summary.get("schema_version") != CHANGE_SUMMARY_VERSION:
        raise KBError("unsupported_schema", "unknown schema_version", ["schema_version"])
    if not isinstance(summary.get("project"), str) or not summary["project"]:
        raise KBError("invalid_input", "project is required", ["project"])
    missing = [f for f in ("services", "files_touched", "change_type") if f not in summary]
    out: dict[str, Any] = {"schema_version": 1, "project": summary["project"]}
    for f in ("services", "files_touched", "change_type", "environment_tags"):
        vals = summary.get(f, [])
        if not isinstance(vals, list) or not all(isinstance(v, str) for v in vals) or len(vals) > 200:
            raise KBError("invalid_input", f"{f} must be a list of strings (max 200)", [f])
        if f == "files_touched":
            vals = [norm_path(v) for v in vals]
        out[f] = sorted(set(vals))
    bad = set(out["change_type"]) - CHANGE_TYPES
    if bad:
        raise KBError("invalid_input", f"invalid change_type: {sorted(bad)}", ["change_type"])
    for f in ("operation", "subsystem", "error_code", "revision", "empty_reason"):
        if summary.get(f) is not None:
            out[f] = bounded(f, str(summary[f]), 200)
    empty = [f for f in ("services", "files_touched", "change_type") if f in summary and not out[f]]
    if empty and not out.get("empty_reason"):
        missing += empty
    return out, sorted(set(missing))


# ---------- condition_json grammar ----------
LIST_FIELDS = {"services", "files_touched", "change_type", "environment_tags"}
SCALAR_FIELDS = {"project", "operation", "subsystem", "error_code", "revision"}
LEAF_OPS = {"eq", "in", "prefix", "exists", "touches_any", "touches_all", "any_in"}
BOOL_OPS = {"all", "any", "not"}

# One-line, redaction-safe hints embedded in error fields so callers can self-correct
# without reading the source.
CONDITION_GRAMMAR_HINT = (
    'example: {"op":"all","args":[{"op":"eq","field":"subsystem","value":"x"},'
    '{"op":"touches_any","field":"files_touched","value":["path"]}]}'
    " | bool ops: all/any/not ({op,args}); leaf ops: eq/in/exists/prefix/touches_any/"
    "touches_all/any_in ({op,field,value})"
)
CHANGE_SUMMARY_HINT = (
    "expected keys: schema_version=1, project, services, files_touched, change_type"
    " | optional: environment_tags, operation, subsystem, error_code, revision, empty_reason"
)


def _invalid_condition(message: str) -> KBError:
    return KBError("invalid_condition", message, [CONDITION_GRAMMAR_HINT])


def validate_condition(node: Any, depth: int = 1, count: list[int] | None = None) -> None:
    count = count if count is not None else [0]
    count[0] += 1
    if depth > MAX_DEPTH or count[0] > MAX_NODES:
        raise _invalid_condition(f"Condition exceeds depth {MAX_DEPTH} or {MAX_NODES} nodes")
    if not isinstance(node, dict) or "op" not in node:
        raise _invalid_condition("Node is missing 'op'")
    op = node["op"]
    if op in BOOL_OPS:
        args = node.get("args")
        if not isinstance(args, list) or not args or (op == "not" and len(args) != 1):
            raise _invalid_condition(f"'{op}' needs valid args")
        if set(node) != {"op", "args"}:
            raise _invalid_condition("Unexpected keys on a boolean node")
        for a in args:
            validate_condition(a, depth + 1, count)
        return
    if op not in LEAF_OPS:
        raise _invalid_condition(f"Operator not allowed: {op}")
    field = node.get("field")
    if field not in LIST_FIELDS | SCALAR_FIELDS:
        raise _invalid_condition(f"Field not allowed: {field}")
    if op == "exists":
        if set(node) != {"op", "field"}:
            raise _invalid_condition("exists only accepts field")
        return
    if set(node) != {"op", "field", "value"}:
        raise _invalid_condition("A leaf node requires op, field, and value")
    v = node["value"]
    if op in {"eq", "prefix"}:
        ok = field in SCALAR_FIELDS and isinstance(v, str)
    elif op == "in":
        ok = field in SCALAR_FIELDS and isinstance(v, list) and all(isinstance(x, str) for x in v)
    else:  # touches_any, touches_all, any_in
        ok = (field in LIST_FIELDS and isinstance(v, list) and 0 < len(v) <= 50
              and all(isinstance(x, str) for x in v))
        if ok and op in {"touches_any", "touches_all"}:
            ok = field == "files_touched" and all(set(x) & set("[]") == set() for x in v)
    if not ok:
        raise _invalid_condition(f"Invalid types for {op}/{field}")


class Missing(Exception):
    def __init__(self, field: str):
        self.field = field


def evaluate(node: dict[str, Any], s: dict[str, Any], trace: list[str]) -> bool:
    op = node["op"]
    if op == "all":
        return all(evaluate(a, s, trace) for a in node["args"])
    if op == "any":
        missing: Missing | None = None
        for a in node["args"]:
            try:
                if evaluate(a, s, trace):
                    return True
            except Missing as m:
                missing = m
        if missing:
            raise missing
        return False
    if op == "not":
        return not evaluate(node["args"][0], s, trace)
    field = node["field"]
    if op == "exists":
        return field in s and s[field] not in ("", [], None)
    if field not in s:
        raise Missing(field)
    val, arg = s[field], node["value"]
    if op == "eq":
        hit = val == arg
    elif op == "in":
        hit = val in arg
    elif op == "prefix":
        hit = isinstance(val, str) and val.startswith(arg)
    elif op == "any_in":
        hit = bool(set(val) & set(arg))
    elif op == "touches_any":
        hit = any(fnmatch.fnmatchcase(p, g) for g in arg for p in val)
    else:  # touches_all
        hit = all(any(fnmatch.fnmatchcase(p, g) for p in val) for g in arg)
    if hit:
        trace.append(f"{op}({field})")
    return hit


# ---------- rules ----------
def rule_hash(project: str, scope: str, condition: dict, invariant: str, action: str,
              severity: str) -> str:
    return sha256(canonical_json({"project": project, "scope": scope, "condition": condition,
                                  "invariant": invariant, "action": action,
                                  "severity": severity}))


def project_root() -> Path:
    """Stable repo root for reading dependency files: the parent of the KB dir
    (default .dfiu), resolved absolutely. Anchoring here instead of the process
    cwd keeps a rule from going falsely 'stale' when the server is launched with
    a different cwd than the project. Derived live from KB_DIR so tests that
    reassign KB_DIR still line up with the files they create under the root."""
    return KB_DIR.resolve().parent


def dependency_fingerprint(paths: list[str], root: Path | None = None) -> str:
    """sha256 of 'path\\0sha256(bytes)\\n' for each declared path, sorted.
    A missing path contributes 'path\\0MISSING'. Directories are not allowed.
    Paths are read relative to the project root, not the process cwd."""
    root = project_root() if root is None else root
    lines = []
    for p in sorted(set(norm_path(x) for x in paths)):
        f = root / p
        digest = hashlib.sha256(f.read_bytes()).hexdigest() if f.is_file() else "MISSING"
        lines.append(f"{p}\0{digest}\n")
    return sha256("".join(lines))


RULE_TRANSITIONS = {
    ("hypothesis", "verified"), ("verified", "active"), ("active", "stale"),
    ("stale", "active"), ("hypothesis", "deprecated"), ("verified", "deprecated"),
    ("active", "deprecated"), ("stale", "deprecated"), ("deprecated", "hypothesis"),
}


def transition(c: sqlite3.Connection, rule: sqlite3.Row, to: str, reason: str, actor: str,
               t: str, extra_sql: str = "", extra_args: tuple = ()) -> None:
    if (rule["status"], to) not in RULE_TRANSITIONS:
        raise KBError("illegal_transition", f"{rule['status']} -> {to} is not allowed", ["status"])
    c.execute(f"UPDATE rules SET status=?, updated_at=?{extra_sql} WHERE id=?",
              (to, t, *extra_args, rule["id"]))
    c.execute("INSERT INTO rule_transitions VALUES(?,?,?,?,?,?,?,?)",
              (str(uuid.uuid4()), rule["id"], rule["status"], to, reason, actor or None,
               rule["revision"], t))


def get_rule(c: sqlite3.Connection, rule_id: str) -> sqlite3.Row:
    row = c.execute("SELECT * FROM rules WHERE id=?", (rule_id,)).fetchone()
    if row is None:
        raise KBError("not_found", "rule_id not found", ["rule_id"])
    return row


def refresh_staleness(c: sqlite3.Connection, project: str, t: str) -> None:
    rows = c.execute("SELECT * FROM rules WHERE project=? AND status='active'", (project,)).fetchall()
    for r in rows:
        reason = None
        if r["valid_until"] and r["valid_until"] <= t:
            reason = "valid_until expired"
        elif r["review_after"] and r["review_after"] <= t:
            reason = "review_after expired"
        elif r["dependency_fingerprint"] and \
                dependency_fingerprint(json.loads(r["dependency_paths_json"])) != r["dependency_fingerprint"]:
            reason = "dependencies changed"
        if reason:
            transition(c, r, "stale", reason, "system", t, ", stale_reason=?", (reason,))


# ---------- recurrence ----------
def title_key(title: str) -> str:
    """Normalized title for near-identical comparison: casefolded words."""
    return " ".join(re.split(r"[^0-9a-z]+", title.casefold())).strip()


def near_identical_title(a: str, b: str) -> bool:
    ka, kb = title_key(a), title_key(b)
    if not ka or not kb:
        return False
    return ka == kb or difflib.SequenceMatcher(None, ka, kb).ratio() >= 0.9


def find_recurrence(c: sqlite3.Connection, project: str, condition_hash: str,
                    title: str) -> str | None:
    """Id of the most recent earlier incident that looks like the same failure, or None."""
    if condition_hash:
        row = c.execute("""SELECT id FROM incidents WHERE project=? AND condition_hash=?
                           ORDER BY created_at DESC LIMIT 1""", (project, condition_hash)).fetchone()
        if row:
            return row["id"]
    for row in c.execute("""SELECT id,title FROM incidents WHERE project=?
                            ORDER BY created_at DESC LIMIT 200""", (project,)):
        if near_identical_title(title, row["title"]):
            return row["id"]
    return None


# ---------- tools ----------
# Every tool states all four behaviour hints explicitly. ToolAnnotations leaves them
# unset by default, and hosts (and directory reviews) need a concrete boolean for each
# one before they can warn the user about what a call will do.
@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False,
                                     idempotentHint=True, openWorldHint=False))
@tool_guard
def record_failure(project: str, title: str, symptom: str, subsystem: str = "",
                   environment: str = "", error_code: str = "", condition_hash: str = "",
                   tags: list[str] | None = None, suspected_cause: str = "",
                   proposed_resolution: str = "", evidence_summary: str = "",
                   proposed_invariant: str = "", proposed_action: str = "",
                   condition: dict[str, Any] | None = None, scope: str = "",
                   severity: str = "warning",
                   dependency_paths: list[str] | None = None,
                   idempotency_key: str = "") -> dict:
    """Open an incident from a fact the user confirmed. Never from a guess that something failed.
    Optionally attach a hypothesis rule. dependency_paths default to the files in touches_any/touches_all.
    suspected_cause and proposed_resolution are stored as proposals; only verify_resolution confirms a fix."""
    request = {k: v for k, v in locals().items() if k != "idempotency_key"}
    warnings: list[str] = []
    with tx() as (c, t):
        cached = idempotent(c, "record_failure", idempotency_key, request)
        if cached:
            return cached
        tags_s = sorted(set(tags or []))
        incident_id = str(uuid.uuid4())
        title_s = scrub("title", title, 240, warnings)
        # A repeat of the same (project, condition_hash), or a near-identical
        # title, warns but never blocks: the call still succeeds.
        prior = find_recurrence(c, bounded("project", project, 160), condition_hash or "", title_s)
        if prior:
            warnings.append(f"possible recurrence of incident {prior}")
        # root_cause/resolution stay NULL: nothing is confirmed yet. The guess lives in
        # the proposed_* columns until an effective verify_resolution writes the truth.
        c.execute("""INSERT INTO incidents(id,created_at,updated_at,project,subsystem,environment,
            title,symptom,error_code,condition_hash,proposed_root_cause,proposed_resolution,
            status,evidence_summary,tags_json,sensitivity) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (incident_id, t, t, bounded("project", project, 160), subsystem or None,
             environment or None, title_s,
             scrub("symptom", symptom, 2000, warnings), error_code or None,
             condition_hash or None,
             scrub("suspected_cause", suspected_cause, 1000, warnings) or None,
             scrub("proposed_resolution", proposed_resolution, 1000, warnings) or None, "open",
             scrub("evidence_summary", evidence_summary, 1000, warnings) or None,
             canonical_json(tags_s), "redacted" if any(": redacted " in w for w in warnings) else "normal"))
        rule_id = None
        if proposed_invariant or condition:
            missing = [n for n, v in (("proposed_invariant", proposed_invariant),
                                      ("proposed_action", proposed_action),
                                      ("condition", condition), ("scope", scope)) if not v]
            if missing:
                raise KBError("invalid_input", "Proposed rule is incomplete", missing)
            if severity not in SEVERITIES:
                raise KBError("invalid_input", "invalid severity", ["severity"])
            validate_condition(condition)
            condition = sanitize_condition(condition, warnings)
            inv = scrub("proposed_invariant", proposed_invariant, 200, warnings)
            act = scrub("proposed_action", proposed_action, 200, warnings)
            # Dependency auto-suggestion: touches_any/touches_all on files_touched
            # seed the rule's dependency_paths, unless the caller sent them explicitly.
            touched: set[str] = set()
            _walk(condition, touched, "files_touched", {"touches_any", "touches_all"})
            dep = dependency_paths if dependency_paths is not None else sorted(touched)
            try:
                dep_paths = sorted(set(norm_path(p) for p in dep))
            except KBError as e:
                raise KBError("invalid_input", e.message, ["dependency_paths"])
            rule_id = "R-" + uuid.uuid4().hex[:12]
            c.execute("""INSERT INTO rules(id,created_at,updated_at,project,scope,title,invariant,
                condition_json,action,status,severity,content_hash,dependency_paths_json)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (rule_id, t, t, project, scope, title_s, inv, canonical_json(condition), act,
                 "hypothesis", severity, rule_hash(project, scope, condition, inv, act, severity),
                 canonical_json(dep_paths)))
            c.execute("INSERT INTO incident_rules VALUES(?,?,?)", (incident_id, rule_id, t))
        elif dependency_paths:
            warnings.append("dependency_paths ignored: no proposed rule was created")
        # Anti-retry nudge: a confirmed failure that no preflight preceded means
        # the KB could not have warned the agent off this change. Informational
        # only -- an MCP server must not block the caller.
        if not had_recent_preflight(c, bounded("project", project, 160), t):
            warnings.append(f"no preflight_check preceded this change for project {project}")
        # Mark 'recurred' only on preflights inside the window before this
        # failure. A preflight from weeks ago is not a recurrence of today's
        # failure. ponytail: time window only, not file/summary matching -- the
        # window kills the bulk of the noise; per-file linkage can come later.
        c.execute("UPDATE preflight_log SET outcome='recurred' WHERE project=? AND outcome='open' "
                  "AND created_at>=?",
                  (bounded("project", project, 160), window_start(t, PREFLIGHT_WINDOW_SECONDS)))
        response = {"ok": True, "incident_id": incident_id, "status": "open", "rule_id": rule_id,
                    "rule_status": "hypothesis" if rule_id else None, "warnings": warnings,
                    "next_step": "verify_resolution"}
        remember(c, "record_failure", idempotency_key, request, response, t)
        return response


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False,
                                     idempotentHint=True, openWorldHint=False))
@tool_guard
def verify_resolution(incident_id: str, verdict: str, method: str, success_criterion: str,
                      preconditions: dict[str, str], exercised_failing_path: bool,
                      evidence_summary: str, rule_id: str = "", environment: str = "",
                      reviewer: str = "", resolution: str = "", root_cause: str = "",
                      idempotency_key: str = "") -> dict:
    """Append evidence the user confirmed by actually trying it. An effective pass needs a criterion, all preconditions passing, and the failing path exercised. Do not call this because you assume the fix worked.
    On an effective pass, resolution and root_cause are written to the incident as the
    confirmed truth (the record-time text stays in proposed_resolution/proposed_root_cause).
    The linked rule's dependency anchor is re-stamped, so activation later refuses if a
    dependency moves after this verification."""
    request = {k: v for k, v in locals().items() if k != "idempotency_key"}
    if verdict not in {"pass", "fail", "inconclusive"}:
        raise KBError("invalid_input", "invalid verdict", ["verdict"])
    if method not in {"test", "reproduction", "regression", "operator_review"}:
        raise KBError("invalid_input", "invalid method", ["method"])
    if not preconditions or any(v not in {"pass", "fail", "inconclusive", "not_run"}
                                for v in preconditions.values()):
        raise KBError("invalid_input", "preconditions: {name: pass|fail|inconclusive|not_run}",
                      ["preconditions"])
    warnings: list[str] = []
    with tx() as (c, t):
        cached = idempotent(c, "verify_resolution", idempotency_key, request)
        if cached:
            return cached
        inc = c.execute("SELECT status FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if inc is None:
            raise KBError("not_found", "incident_id not found", ["incident_id"])
        rule = None
        if rule_id:
            rule = get_rule(c, rule_id)
            linked = c.execute("SELECT 1 FROM incident_rules WHERE incident_id=? AND rule_id=?",
                               (incident_id, rule_id)).fetchone()
            if not linked:
                raise KBError("invalid_input", "rule_id is not linked to this incident", ["rule_id"])
        pending = sorted(k for k, v in preconditions.items() if v != "pass")
        if not exercised_failing_path:
            pending.append("exercised_failing_path")
        if method == "operator_review":
            pending.append("method: operator_review is not an effective pass")
        if not success_criterion.strip():
            pending.append("success_criterion")
        effective = verdict == "pass" and not pending
        c.execute("""INSERT INTO verification_log(id,incident_id,rule_id,created_at,verdict,method,
            success_criterion,preconditions_json,exercised_failing_path,environment,
            evidence_summary,reviewer) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (str(uuid.uuid4()), incident_id, rule_id or None, t, verdict, method,
             scrub("success_criterion", success_criterion, 500, warnings),
             canonical_json(preconditions), int(exercised_failing_path), environment or None,
             scrub("evidence_summary", evidence_summary, 2000, warnings), reviewer or None))
        new_inc = inc["status"]
        if effective:
            new_inc = "verified_resolved"
        elif verdict == "fail" and inc["status"] == "verified_resolved":
            new_inc = "reopened"
        if new_inc != inc["status"]:
            c.execute("UPDATE incidents SET status=?, updated_at=? WHERE id=?", (new_inc, t, incident_id))
        # The confirmed fix overwrites the incident's resolution; the record-time guess
        # stays in proposed_resolution. Empty strings change nothing.
        confirmed = [(column, provided) for column, provided in
                     (("resolution", resolution), ("root_cause", root_cause)) if provided.strip()]
        if effective and confirmed:
            assigns = ", ".join(f"{column}=?" for column, _ in confirmed)
            values = [scrub(column, provided, 1000, warnings) for column, provided in confirmed]
            c.execute(f"UPDATE incidents SET {assigns}, updated_at=? WHERE id=?",
                      (*values, t, incident_id))
        rule_status = rule["status"] if rule else None
        if rule is not None and effective:
            # Anchor the rule's dependency fingerprint to *this* verification, so a
            # later dependency change is detectable at activation even while the rule
            # is still only 'verified' (refresh_staleness only scans 'active' rules).
            rule_paths = json.loads(rule["dependency_paths_json"])
            anchor = dependency_fingerprint(rule_paths) if rule_paths else None
            c.execute("UPDATE rules SET last_verified_at=?, dependency_fingerprint=?, updated_at=? "
                      "WHERE id=?", (t, anchor, t, rule_id))
            if rule["status"] == "hypothesis":
                transition(c, rule, "verified", "verify_resolution pass", reviewer, t)
                rule_status = "verified"
        elif rule is not None and verdict == "fail":
            c.execute("UPDATE rules SET confidence=max(0, confidence-0.2), updated_at=? WHERE id=?",
                      (t, rule_id))
        # Same anti-retry nudge as record_failure: a confirmation with no recent
        # preflight means the KB had no chance to warn. Informational, never blocks.
        inc_project = c.execute("SELECT project FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if inc_project and not had_recent_preflight(c, inc_project["project"], t):
            warnings.append(f"no preflight_check preceded this change for project {inc_project['project']}")
        if effective and not resolution.strip():
            warnings.append("resolution not recorded: send `resolution` with the confirmed fix")
        response = {"ok": True, "incident_id": incident_id, "verdict": verdict,
                    "effective_pass": effective, "incident_status": new_inc,
                    "rule_status": rule_status, "resolution_confirmed": bool(resolution.strip()),
                    "pending_requirements": pending, "warnings": warnings}
        remember(c, "verify_resolution", idempotency_key, request, response, t)
        return response


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False,
                                     idempotentHint=False, openWorldHint=False))
@tool_guard
def activate_rule(rule_id: str, reviewer: str, reason: str, dependency_paths: list[str] | None = None,
                  review_after: str = "", valid_until: str = "",
                  severity: str = "") -> dict:
    """Move verified or stale to active. Needs a reviewer and an effective verification after the last change."""
    if not reviewer or not reason:
        raise KBError("invalid_input", "reviewer and reason are required", ["reviewer", "reason"])
    with tx() as (c, t):
        r = get_rule(c, rule_id)
        if r["status"] not in {"verified", "stale"}:
            raise KBError("illegal_transition", f"{r['status']} -> active is not allowed", ["status"])
        last_stale = c.execute("SELECT max(created_at) FROM rule_transitions "
                               "WHERE rule_id=? AND to_status='stale'", (rule_id,)).fetchone()[0]
        if not r["last_verified_at"] or (r["status"] == "stale" and
                                         r["last_verified_at"] <= (last_stale or "")):
            raise KBError("verification_required", "An effective verification is missing for the current context",
                          ["verify_resolution"])
        sev = severity or r["severity"]
        if sev not in SEVERITIES:
            raise KBError("invalid_input", "invalid severity", ["severity"])
        # dependency_paths=None inherits the paths stored on the rule (for example
        # auto-suggested at record time) instead of wiping them. An explicit list wins.
        if dependency_paths is None:
            dependency_paths = json.loads(r["dependency_paths_json"])
        paths = sorted(set(norm_path(p) for p in (dependency_paths or [])))
        fp = dependency_fingerprint(paths) if paths else None
        # A 'verified' rule is not scanned by refresh_staleness (it only walks active
        # rules), so the anchor is the only thing that can notice a dependency moved
        # between verification and activation. A moved anchor means the evidence no
        # longer covers the current dependency state: verify again, then promote.
        if r["dependency_fingerprint"] is not None and fp != r["dependency_fingerprint"]:
            raise KBError("verification_required",
                          "dependencies changed since the last effective verification; "
                          "call verify_resolution again",
                          ["verify_resolution", "dependency_paths"])
        rev = r["revision"] + (1 if r["status"] == "stale" else 0)
        h = rule_hash(r["project"], r["scope"], json.loads(r["condition_json"]), r["invariant"],
                      r["action"], sev)
        transition(c, r, "active", reason, reviewer, t,
                   ", severity=?, revision=?, content_hash=?, dependency_paths_json=?, "
                   "dependency_fingerprint=?, review_after=?, valid_until=?, "
                   "stale_reason=NULL",
                   (sev, rev, h, canonical_json(paths), fp,
                    review_after or None, valid_until or None))
        return {"ok": True, "rule_id": rule_id, "status": "active", "revision": rev,
                "content_hash": h, "dependency_fingerprint": fp}


# Retiring a rule withdraws a guard other changes relied on, so it is reported as
# destructive even though the row and its history are kept.
@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True,
                                     idempotentHint=False, openWorldHint=False))
@tool_guard
def deprecate_rule(rule_id: str, reason: str, reviewer: str, evidence_ref: str = "") -> dict:
    """Any status except deprecated becomes deprecated. A reason is required. History stays."""
    if not reason or not reviewer:
        raise KBError("invalid_input", "reason and reviewer are required", ["reason", "reviewer"])
    with tx() as (c, t):
        r = get_rule(c, rule_id)
        why = reason + (f" [ref:{evidence_ref}]" if evidence_ref else "")
        transition(c, r, "deprecated", why, reviewer, t,
                   ", deprecated_at=?, deprecation_reason=?", (t, bounded("reason", why, 500)))
        return {"ok": True, "rule_id": rule_id, "status": "deprecated", "deprecated_at": t}


def build_artifacts(c: sqlite3.Connection, project: str) -> tuple[str, str, int]:
    rows = c.execute("""SELECT id,scope,severity,invariant,action,condition_json,revision,content_hash
        FROM rules WHERE project=? AND status='active' ORDER BY scope,id""", (project,)).fetchall()
    rules = []
    for r in rows:
        inc = [x[0] for x in c.execute(
            "SELECT incident_id FROM incident_rules WHERE rule_id=? ORDER BY incident_id", (r["id"],))]
        rules.append({"id": r["id"], "scope": r["scope"], "severity": r["severity"],
                      "invariant": r["invariant"], "action": r["action"],
                      "when": json.loads(r["condition_json"]), "revision": r["revision"],
                      "content_hash": r["content_hash"], "incident_ids": inc[:5]})
    doc = {"schema_version": SCHEMA_VERSION, "project": project, "rules": rules}
    js = canonical_json(doc, indent=2) + "\n"
    md = [f"# Active rules: {project}", ""]
    for r in rules:
        md.append(f"- [{r['severity']}] `{r['id']}` ({r['scope']}): {r['invariant']} -> {r['action']}")
    md_s = "\n".join(md) + "\n"
    return js, md_s, len(rules)


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False,
                                     idempotentHint=False, openWorldHint=False))
@tool_guard
def compile_artifacts(project: str, write: bool = True) -> dict:
    """Write canonical invariants.json and active_rules.md under ARTIFACT_DIR."""
    with tx() as (c, t):
        refresh_staleness(c, project, t)
        js, md, n = build_artifacts(c, project)
        h = sha256(js)
        if write:
            atomic_write(ARTIFACT_DIR / "invariants.json", js)
            atomic_write(ARTIFACT_DIR / "active_rules.md", md)
        return {"ok": True, "project": project, "rule_count": n, "artifact_sha256": h,
                "written": write, "files": ["invariants.json", "active_rules.md"] if write else []}


# readOnlyHint is false on purpose: refreshing staleness is a write (an expired rule is
# transitioned to 'stale' and journalled). A host that needs a strictly non-writing call
# should use preflight_stats or get_incident_details instead.
@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False,
                                     idempotentHint=True, openWorldHint=False))
@tool_guard
def list_active_invariants(project: str, scope: str = "", severity: str = "",
                           limit: int = 50) -> dict:
    """Compact list of active rules, plus the hash of the full canonical artifact."""
    limit = max(1, min(limit, 200))
    with tx() as (c, t):
        refresh_staleness(c, project, t)
        js, _, total = build_artifacts(c, project)
    rules = [{"id": r["id"], "scope": r["scope"], "severity": r["severity"],
              "invariant": r["invariant"], "action": r["action"]}
             for r in json.loads(js)["rules"]
             if (not scope or r["scope"] == scope) and (not severity or r["severity"] == severity)]
    return {"ok": True, "rules": rules[:limit], "count": len(rules), "truncated": len(rules) > limit,
            "total_active": total, "artifact_sha256": sha256(js)}


_CODE_EXT = {".py", ".js", ".ts", ".tsx", ".go", ".rs", ".java", ".c", ".h", ".cpp", ".rb", ".php"}
_CONFIG_EXT = {".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf"}
_DEP_NAMES = {"package.json", "package-lock.json", "requirements.txt", "poetry.lock",
              "cargo.lock", "go.sum", "go.mod", "uv.lock", "pipfile.lock", "pyproject.toml"}


def _git(root: Path, args: list[str]) -> list[str] | None:
    env = os.environ.copy()
    env.pop("GIT_DIR", None)
    env.pop("GIT_WORK_TREE", None)
    try:
        proc = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True,
                              timeout=5, env=env)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return [ln.strip().replace("\\", "/") for ln in proc.stdout.splitlines() if ln.strip()]


def _kb_prefixes_under(root: Path) -> tuple[str, ...]:
    """Project-relative prefixes of the KB's own directories, when they sit under root.
    The database, its WAL sidecars, and the compiled artifacts are state, not a change."""
    prefixes = []
    for d in (KB_DIR, ARTIFACT_DIR):
        try:
            rel = d.resolve().relative_to(root.resolve())
        except (ValueError, OSError):
            continue
        if rel.parts:
            prefixes.append(str(PurePosixPath(*rel.parts)).strip("/") + "/")
    return tuple(sorted(set(prefixes)))


def git_changes(root: Path = Path(".")) -> list[str] | None:
    """Names from git diff when cwd is the work-tree root. None when it is not a repo,
    or when the cwd is inside a repo but not at its root (the union then cannot run).
    The KB's own files are filtered out so they never count as changed source."""
    if _git(root, ["rev-parse", "--is-inside-work-tree"]) != ["true"]:
        return None
    top = _git(root, ["rev-parse", "--show-toplevel"])
    if not top or Path(top[0]).resolve() != root.resolve():
        return None
    files: set[str] = set()
    for args in (["diff", "--name-only"], ["diff", "--name-only", "--cached"],
                 ["ls-files", "--others", "--exclude-standard"]):
        files.update(_git(root, args) or [])
    blocked = _kb_prefixes_under(root)
    return sorted(f for f in files if not f.startswith(blocked))


def infer_change_types(paths: list[str]) -> list[str]:
    out: set[str] = set()
    for p in paths:
        name = PurePosixPath(p).name.lower()
        low = p.lower()
        if name.startswith("test_") or name.endswith("_test.py") or "/tests/" in f"/{low}" or low.startswith("tests/"):
            out.add("test")
        if name in {"dockerfile", "compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.yaml"} or "compose" in name:
            out.add("infra")
        if name in _DEP_NAMES or name.endswith(".lock"):
            out.add("dependency")
        ext = PurePosixPath(name).suffix
        if ext in {".md", ".rst"}:
            out.add("docs")
        elif ext in _CONFIG_EXT:
            out.add("config")
        elif ext == ".sql":
            out.add("schema")
        elif ext in {".hex", ".elf", ".uf2"}:
            out.add("firmware")
        elif ext in _CODE_EXT:
            out.add("code")
    return sorted(out & CHANGE_TYPES)


GIT_SKIPPED_NOTE = ("git union skipped: cwd is not the git work-tree root, so "
                    "files_touched holds only what the caller sent")


def enrich_summary(summary: dict[str, Any], root: Path = Path(".")) -> tuple[dict[str, Any], list[str], str]:
    """Union of the agent's summary and the git diff. The agent may add files. It cannot
    hide files git already shows. Returns (summary, git files, note); the note is non-empty
    when the union could not run even though the directory is inside a git work tree, so a
    silently weakened check is never mistaken for a clean one."""
    summary = dict(summary)
    found = git_changes(root)
    if found is None:
        in_repo = _git(root, ["rev-parse", "--is-inside-work-tree"]) == ["true"]
        return summary, [], GIT_SKIPPED_NOTE if in_repo else ""
    if not found:
        return summary, [], ""
    given = summary.get("files_touched")
    summary["files_touched"] = [*(given if isinstance(given, list) else []), *found]
    types = summary.get("change_type")
    extra = infer_change_types(found)
    if extra:
        summary["change_type"] = [*(types if isinstance(types, list) else []), *extra]
    return summary, found, ""


def _walk(node: Any, acc: set[str], field: str, ops: set[str]) -> None:
    if not isinstance(node, dict):
        return
    if node.get("op") in BOOL_OPS:
        for arg in node.get("args") or []:
            _walk(arg, acc, field, ops)
        return
    if node.get("field") != field or node.get("op") not in ops:
        return
    val = node.get("value")
    vals = [val] if isinstance(val, str) else val if isinstance(val, list) else []
    for raw in vals:
        if isinstance(raw, str) and raw:
            acc.add(raw)


def variant_note(condition: dict[str, Any], s: dict[str, Any]) -> str | None:
    """Near miss: same directory, or the same first token of error_code.
    ponytail: first token only. No text similarity."""
    dirs: set[str] = set()
    raw_paths: set[str] = set()
    _walk(condition, raw_paths, "files_touched", {"touches_any", "touches_all", "any_in"})
    for raw in raw_paths:
        head = raw.split("*", 1)[0].split("?", 1)[0].rstrip("/")
        if not head:
            continue
        if "*" in raw or "?" in raw:
            dirs.add(head)
        else:
            parent = str(PurePosixPath(head).parent)
            if parent not in ("", "."):
                dirs.add(parent)
    for f in s.get("files_touched") or []:
        parent = str(PurePosixPath(f).parent)
        if parent not in ("", ".") and parent in dirs:
            return "same directory"
    codes: set[str] = set()
    _walk(condition, codes, "error_code", {"eq", "prefix", "in"})
    got = s.get("error_code") or ""

    def stem(c: str) -> str:
        parts = re.split(r"[_\-.:/]", c)
        return parts[0] if len(parts) > 1 and len(parts[0]) >= 3 else ""

    g = stem(got)
    if g and any(stem(c) == g and c != got for c in codes):
        return "related error_code"
    return None


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False,
                                     idempotentHint=False, openWorldHint=False))
@tool_guard
def preflight_check(summary: dict[str, Any], limit: int = MAX_MATCHES) -> dict:
    """Evaluate a ChangeSummaryV1. Git names are merged in. Hypotheses and variants warn. They do not block."""
    summary, git_files, git_note = enrich_summary(summary)
    try:
        s, missing_fields = normalize_summary(summary)
    except KBError as e:
        if CHANGE_SUMMARY_HINT not in e.fields:
            e.fields.append(CHANGE_SUMMARY_HINT)
        raise
    limit = max(1, min(limit, MAX_MATCHES))
    with tx() as (c, t):
        refresh_staleness(c, s["project"], t)
        js, _, _ = build_artifacts(c, s["project"])
        rows = c.execute("""SELECT id,scope,severity,invariant,action,condition_json,status
            FROM rules WHERE project=? AND status IN ('active','stale','hypothesis','verified')
            ORDER BY scope,id""", (s["project"],)).fetchall()
        links = {r["id"]: [x[0] for x in c.execute(
            "SELECT incident_id FROM incident_rules WHERE rule_id=? ORDER BY incident_id LIMIT 3",
            (r["id"],))] for r in rows}
    sev_rank = {"blocker": 0, "warning": 1, "info": 2}
    matches, insufficient, stale_hits, hypo_hits, variants = [], set(), [], [], []
    for r in rows:
        condition = json.loads(r["condition_json"])
        trace: list[str] = []
        try:
            hit = evaluate(condition, s, trace)
        except Missing as m:
            insufficient.add(m.field)
            continue
        if not hit:
            note = variant_note(condition, s)
            if note:
                variants.append({"rule_id": r["id"], "invariant": r["invariant"], "note": note})
            continue
        if r["status"] == "stale":
            stale_hits.append({"rule_id": r["id"], "invariant": r["invariant"]})
        elif r["status"] in {"hypothesis", "verified"}:
            note = "hypothesis, does not block" if r["status"] == "hypothesis" else "verified, not activated"
            hypo_hits.append({"rule_id": r["id"], "invariant": r["invariant"], "note": note, "severity": "info"})
        else:
            matches.append({"rule_id": r["id"], "severity": r["severity"], "invariant": r["invariant"],
                            "action": r["action"], "matched": trace, "incident_ids": links[r["id"]]})
    matches.sort(key=lambda m: (sev_rank[m["severity"]], m["rule_id"]))
    hypo_hits.sort(key=lambda m: m["rule_id"])
    variants.sort(key=lambda m: m["rule_id"])
    missing_all = sorted(set(missing_fields) | insufficient)
    soft = stale_hits or hypo_hits or variants
    if matches or soft:
        status = "alert"
    elif missing_all:
        status = "insufficient_context"
    elif not rows:
        status = "no_coverage"
    else:
        status = "clear"
    rule_ids = sorted({m["rule_id"] for m in (*matches, *stale_hits, *hypo_hits, *variants)})
    with tx() as (c, t):
        c.execute("INSERT INTO preflight_log VALUES(?,?,?,?,?,?,?,?)",
                  (str(uuid.uuid4()), s["project"], t, status, sha256(canonical_json(s)),
                   canonical_json(s.get("files_touched") or []), canonical_json(rule_ids), "open"))
    heard = bool(matches or hypo_hits or stale_hits or variants)
    return {"ok": True, "status": status, "matches": matches[:limit],
            "hypothesis_matches": hypo_hits[:limit],
            "stale_matches": [{"rule_id": m["rule_id"], "invariant": m["invariant"],
                               "note": "needs revalidation"} for m in stale_hits[:limit]],
            "variant_matches": variants[:limit],
            "evaluated": len(rows), "missing_fields": missing_all,
            "artifact_sha256": sha256(js), "git_files": git_files, "git_note": git_note,
            "next_tool": "get_incident_details" if heard else None}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False,
                                     idempotentHint=True, openWorldHint=False))
@tool_guard
def preflight_stats(project: str) -> dict:
    """How many preflights ran, and how many were followed by an incident. It does not count checks that never happened."""
    project = bounded("project", project, 160)
    with tx() as (c, _):
        rows = c.execute("""SELECT status, outcome, COUNT(*) n FROM preflight_log
                            WHERE project=? GROUP BY status, outcome""", (project,)).fetchall()
    by_status: dict[str, int] = {}
    recurred_after: dict[str, int] = {}
    runs = 0
    for r in rows:
        by_status[r["status"]] = by_status.get(r["status"], 0) + r["n"]
        runs += r["n"]
        if r["outcome"] == "recurred":
            recurred_after[r["status"]] = r["n"]
    return {"ok": True, "project": project, "runs": runs, "by_status": by_status,
            "recurred_after": recurred_after}


SECTIONS = {"summary": ("title", "symptom", "error_code", "status", "subsystem", "environment"),
            "cause": ("root_cause",), "resolution": ("resolution",),
            "proposal": ("proposed_root_cause", "proposed_resolution"),
            "references": ("evidence_summary", "evidence_ref")}


def _related_row(x: sqlite3.Row, max_chars: int) -> dict[str, Any]:
    """One recurrence-family row: id, title, status, created_at, short resolution."""
    hidden = x["sensitivity"] == "restricted"
    short = min(max_chars, 200)
    return {"id": x["id"],
            "title": "[RESTRICTED]" if hidden else redact(x["title"])[0][:short],
            "status": x["status"],
            "created_at": x["created_at"],
            "resolution": None if x["resolution"] is None else
                          ("[RESTRICTED]" if hidden else redact(x["resolution"])[0][:short])}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False,
                                     idempotentHint=True, openWorldHint=False))
@tool_guard
def get_incident_details(incident_id: str, sections: list[str] | None = None,
                         max_chars: int = 2000) -> dict:
    """Bounded detail for one incident, looked up by exact id. Text is redacted again.
    related_incidents lists other incidents sharing the same condition_hash.
    resolution is the confirmed fix only (empty until an effective verify_resolution); the
    record-time guess is under proposed_resolution. resolution_confirmed states which."""
    sections = sorted(set(sections or ["summary", "cause", "resolution", "proposal",
                                       "verification", "related_incidents"]))
    bad = set(sections) - set(SECTIONS) - {"verification", "related_incidents"}
    if bad:
        raise KBError("invalid_input", f"invalid sections: {sorted(bad)}", ["sections"])
    max_chars = max(200, min(max_chars, 8000))
    c = _open()
    try:
        row = c.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if row is None:
            raise KBError("not_found", "incident_id not found", ["incident_id"])
        logs = c.execute("""SELECT verdict,method,created_at,evidence_summary FROM verification_log
            WHERE incident_id=? ORDER BY created_at DESC LIMIT 5""", (incident_id,)).fetchall()
        related: list[sqlite3.Row] = []
        if row["condition_hash"]:
            related = c.execute("""SELECT id,title,status,created_at,resolution,sensitivity
                FROM incidents WHERE condition_hash=? AND id<>?
                ORDER BY created_at DESC LIMIT 5""", (row["condition_hash"], incident_id)).fetchall()
    finally:
        c.close()
    restricted = row["sensitivity"] == "restricted"
    out: dict[str, Any] = {"ok": True, "incident_id": incident_id, "sensitivity": row["sensitivity"],
                           "resolution_confirmed": row["status"] == "verified_resolved"}
    for sec in sections:
        if sec == "related_incidents":
            out["related_incidents"] = [_related_row(x, max_chars) for x in related]
            continue
        if sec == "verification":
            out["verifications"] = [{**dict(x), "evidence_summary":
                                     redact(x["evidence_summary"])[0][:max_chars]} for x in logs]
            continue
        for key in SECTIONS[sec]:
            val = row[key]
            if val is None:
                continue
            if restricted and key not in ("title", "status", "error_code"):
                out[key] = "[RESTRICTED]"
            else:
                out[key] = redact(str(val))[0][:max_chars]
    return out


INCIDENT_STATUSES = ("open", "change_applied_unverified", "verified_resolved",
                     "reopened", "closed")
# Fields a keyword is matched against, with AND between terms and OR across fields.
SEARCH_FIELDS = ("title", "symptom", "error_code", "subsystem", "root_cause", "resolution",
                 "proposed_root_cause", "proposed_resolution", "evidence_summary", "tags_json")
MAX_SEARCH_TERMS = 8


def escape_like(value: str) -> str:
    """Escape LIKE metacharacters so a keyword or tag is matched literally."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _browse_row(x: sqlite3.Row, max_chars: int) -> dict[str, Any]:
    """One browse row: identity, key fields, tags, and a short redacted resolution.
    A restricted incident exposes title, status, and error_code only, like get_incident_details."""
    hidden = x["sensitivity"] == "restricted"
    short = min(max_chars, 200)
    subsystem = x["subsystem"]
    if hidden and subsystem is not None:
        subsystem = "[RESTRICTED]"
    resolution = x["resolution"]
    if resolution is not None:
        resolution = "[RESTRICTED]" if hidden else redact(resolution)[0][:short]
    return {"id": x["id"], "project": x["project"], "status": x["status"],
            "title": redact(x["title"])[0][:short], "created_at": x["created_at"],
            "subsystem": subsystem, "error_code": x["error_code"],
            "condition_hash": x["condition_hash"], "tags": json.loads(x["tags_json"]),
            "resolution": resolution}


@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False,
                                     idempotentHint=True, openWorldHint=False))
@tool_guard
def list_incidents(project: str = "", query: str = "", incident_id: str = "", subsystem: str = "",
                   status: str = "", error_code: str = "", condition_hash: str = "", tag: str = "",
                   since: str = "", limit: int = 20, max_chars: int = 200) -> dict:
    """Browse the incident memory: by exact id, by keywords, or by key fields. Read-only.
    Filters combine with AND. incident_id/project/subsystem/status/condition_hash are exact,
    error_code is a prefix, tag is exact membership, since is created_at >= an ISO stamp.
    query is split on whitespace and every term must appear in some searched field.
    With no filter at all it lists the most recent incidents. Rows are compact: use
    get_incident_details for the full write-up behind an id."""
    limit = max(1, min(limit, 100))
    max_chars = max(200, min(max_chars, 2000))
    where: list[str] = []
    args: list[Any] = []
    if incident_id:
        where.append("id=?")
        args.append(bounded("incident_id", incident_id, 100))
    if project:
        where.append("project=?")
        args.append(bounded("project", project, 160))
    if subsystem:
        where.append("subsystem=?")
        args.append(bounded("subsystem", subsystem, 200))
    if status:
        if status not in INCIDENT_STATUSES:
            raise KBError("invalid_input", f"status must be one of {list(INCIDENT_STATUSES)}",
                          ["status"])
        where.append("status=?")
        args.append(status)
    if error_code:
        where.append("error_code LIKE ? ESCAPE '\\'")
        args.append(escape_like(bounded("error_code", error_code, 200)) + "%")
    if condition_hash:
        where.append("condition_hash=?")
        args.append(bounded("condition_hash", condition_hash, 200))
    if tag:
        where.append("tags_json LIKE ? ESCAPE '\\'")
        args.append(f'%"{escape_like(bounded("tag", tag, 60))}"%')
    if since:
        where.append("created_at>=?")
        args.append(bounded("since", since, 40))
    for term in bounded("query", query, 400).split()[:MAX_SEARCH_TERMS]:
        pattern = f"%{escape_like(term)}%"
        where.append("(" + " OR ".join(
            f"COALESCE({field},'') LIKE ? ESCAPE '\\'" for field in SEARCH_FIELDS) + ")")
        args.extend([pattern] * len(SEARCH_FIELDS))
    sql = "SELECT * FROM incidents"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY created_at DESC, id LIMIT ?"
    args.append(limit + 1)          # one extra row tells us whether we truncated
    c = _open()
    try:
        rows = c.execute(sql, tuple(args)).fetchall()
    finally:
        c.close()
    return {"ok": True, "count": min(len(rows), limit), "truncated": len(rows) > limit,
            "incidents": [_browse_row(x, max_chars) for x in rows[:limit]],
            "next_tool": "get_incident_details" if len(rows) == 1 else None}


if __name__ == "__main__":
    migrate()
    mcp.run(transport="stdio")
