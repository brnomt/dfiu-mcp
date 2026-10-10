"""Suite MVP §12. Reloj e ids inyectados; SQLite y artefactos temporales."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import server

PROJECT = "pterodactyl"
COND = {"op": "eq", "field": "project", "value": PROJECT}
STATUSES = ("hypothesis", "verified", "active", "stale", "deprecated")
SECRETS = {
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIBfakekey\n-----END RSA PRIVATE KEY-----",
    "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
    "github_token": "ghp_" + "a" * 36,
    "slack_token": "xoxb-1234567890-abcdef",
    "openai_like_key": "sk-" + "a" * 20,
    "google_api_key": "AIza" + "a" * 35,
    "jwt": "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.signature",
    "auth_header": "Authorization: Bearer supertoken",
    "url_credentials": "https://user:s3cret@example.com/x",
    "assignment": "DB_PASSWORD=supersecret",
}
ENTROPY = "mZ9kQ2wE8rT5yU1iO4pA7sD0fG3hJ6"


class Clock:
    def __init__(self) -> None:
        self.t = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self) -> str:
        return self.t.isoformat(timespec="microseconds")

    def advance(self, seconds: int = 1) -> None:
        self.t += timedelta(seconds=seconds)


class Ids:
    def __init__(self) -> None:
        self.n = 0

    def __call__(self) -> uuid.UUID:
        self.n += 1
        # hex[:12] is the rule id; the counter lives in the high bits.
        return uuid.UUID(int=self.n << 96)


class Net(BaseException):
    pass


class MVP(unittest.TestCase):
    def setUp(self) -> None:
        self._cwd = os.getcwd()
        self._now = server.now
        self._uuid4 = server.uuid.uuid4
        self._kb = server.KB_DIR
        self._db = server.DB
        self._art = server.ARTIFACT_DIR
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        os.chdir(self.root)
        server.KB_DIR = self.root / "kb"
        server.DB = server.KB_DIR / "kb.sqlite3"
        server.ARTIFACT_DIR = self.root / "art"
        self.clock = Clock()
        self.ids = Ids()
        server.now = self.clock  # type: ignore[assignment]
        server.uuid.uuid4 = self.ids  # type: ignore[method-assign]
        server.migrate()

    def tearDown(self) -> None:
        server.now = self._now
        server.uuid.uuid4 = self._uuid4
        server.KB_DIR = self._kb
        server.DB = self._db
        server.ARTIFACT_DIR = self._art
        os.chdir(self._cwd)
        self.tmp.cleanup()

    def summary(self, **kw: object) -> dict:
        base: dict = {
            "schema_version": 1, "project": PROJECT,
            "services": ["node"], "files_touched": ["deploy/compose.yaml"],
            "change_type": ["config"],
        }
        base.update(kw)
        return base

    def record(self, **kw: object) -> dict:
        args: dict = dict(
            project=PROJECT, title="titulo", symptom="sintoma",
            proposed_invariant="no repetir el fallo", proposed_action="detener",
            condition=COND, scope="deploy", severity="warning",
        )
        args.update(kw)
        return server.record_failure(**args)

    def verify(self, incident_id: str, rule_id: str = "", **kw: object) -> dict:
        args: dict = dict(
            incident_id=incident_id, verdict="pass", method="test",
            success_criterion="el sintoma no reaparece",
            preconditions={"db": "pass"}, exercised_failing_path=True,
            evidence_summary="ok", rule_id=rule_id, reviewer="ana",
        )
        args.update(kw)
        return server.verify_resolution(**args)

    def activate(self, rule_id: str, **kw: object) -> dict:
        args: dict = dict(rule_id=rule_id, reviewer="ana", reason="revisado")
        args.update(kw)
        return server.activate_rule(**args)

    def q(self, sql: str, args: tuple = ()) -> list:
        with server.tx() as (c, _):
            return list(c.execute(sql, args))

    def test_migrations_and_permissions(self) -> None:
        server.migrate()
        with server.tx() as (c, _):
            self.assertEqual(c.execute("PRAGMA user_version").fetchone()[0], 2)
            self.assertEqual(c.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        self.assertEqual(server.KB_DIR.stat().st_mode & 0o777, 0o700)
        self.assertEqual(server.DB.stat().st_mode & 0o777, 0o600)

    def test_compiler_is_deterministic(self) -> None:
        rec = self.record(proposed_action="check cañón", scope="zeta")
        self.verify(rec["incident_id"], rec["rule_id"])
        self.activate(rec["rule_id"])
        other = self.record(scope="alpha", proposed_invariant="other rule",
                            proposed_action="parar", severity="info",
                            condition={"op": "eq", "field": "project", "value": PROJECT})
        self.verify(other["incident_id"], other["rule_id"])
        self.activate(other["rule_id"])
        with server.tx() as (c, t):
            for i in range(6):
                iid = f"extra-{i:02d}"
                c.execute(
                    """INSERT INTO incidents(id,created_at,updated_at,project,title,symptom,status)
                       VALUES(?,?,?,?,?,?,?)""",
                    (iid, t, t, PROJECT, "t", "s", "open"))
                c.execute("INSERT INTO incident_rules VALUES(?,?,?)", (iid, rec["rule_id"], t))
        bodies, hashes, mds = [], [], []
        for _ in range(5):
            out = server.compile_artifacts(PROJECT)
            raw = (server.ARTIFACT_DIR / "invariants.json").read_bytes()
            bodies.append(raw)
            hashes.append(out["artifact_sha256"])
            mds.append((server.ARTIFACT_DIR / "active_rules.md").read_bytes())
        self.assertEqual(len(set(bodies)), 1)
        self.assertEqual(len(set(mds)), 1)
        self.assertEqual(set(hashes), {hashlib.sha256(bodies[0]).hexdigest()})
        text = bodies[0].decode()
        self.assertNotIn("generated_at", text)
        self.assertNotIn("\\u00", text)
        self.assertIn("cañón", text)
        self.assertTrue(text.endswith("\n"))
        self.assertEqual(text, server.canonical_json(json.loads(text), indent=2) + "\n")
        rules = json.loads(text)["rules"]
        self.assertEqual([r["scope"] for r in rules], ["alpha", "zeta"])
        zeta = next(r for r in rules if r["scope"] == "zeta")
        self.assertEqual(zeta["incident_ids"], sorted(zeta["incident_ids"])[:5])
        self.assertLessEqual(len(zeta["incident_ids"]), 5)
        line = (server.ARTIFACT_DIR / "active_rules.md").read_text().splitlines()[2]
        self.assertTrue(line.startswith("- [info] `"))
        bare = server.compile_artifacts("empty")
        self.record(proposed_invariant="changes the hash", proposed_action="x", scope="other")
        # a hypothesis is not compiled; a semantic change to an active rule is
        self.assertEqual(server.compile_artifacts("empty")["artifact_sha256"], bare["artifact_sha256"])
        added = self.record(project="empty", proposed_invariant="changes", proposed_action="x",
                            scope="s", condition={"op": "eq", "field": "project", "value": "empty"})
        self.verify(added["incident_id"], added["rule_id"])
        self.activate(added["rule_id"])
        self.assertNotEqual(server.compile_artifacts("empty")["artifact_sha256"], bare["artifact_sha256"])

    def test_grammar(self) -> None:
        s = {
            "project": PROJECT, "services": ["node", "db"],
            "files_touched": ["deploy/compose.yaml", "src/a.py"],
            "change_type": ["config"], "operation": "deploy", "revision": "abc",
        }
        cases = [
            ({"op": "eq", "field": "project", "value": PROJECT}, True),
            ({"op": "eq", "field": "project", "value": "otro"}, False),
            ({"op": "prefix", "field": "operation", "value": "dep"}, True),
            ({"op": "prefix", "field": "operation", "value": "xyz"}, False),
            ({"op": "in", "field": "revision", "value": ["abc", "def"]}, True),
            ({"op": "in", "field": "revision", "value": ["no"]}, False),
            ({"op": "exists", "field": "operation"}, True),
            ({"op": "exists", "field": "subsystem"}, False),
            ({"op": "any_in", "field": "services", "value": ["db", "cache"]}, True),
            ({"op": "any_in", "field": "services", "value": ["cache"]}, False),
            ({"op": "touches_any", "field": "files_touched", "value": ["deploy/*"]}, True),
            ({"op": "touches_any", "field": "files_touched", "value": ["nope/*"]}, False),
            ({"op": "touches_all", "field": "files_touched", "value": ["deploy/*", "src/*"]}, True),
            ({"op": "touches_all", "field": "files_touched", "value": ["deploy/*", "missing/*"]}, False),
            ({"op": "touches_all", "field": "files_touched", "value": ["deploy/*"]}, False),  # filler, not evaluated here
        ]
        empty = dict(s, files_touched=[])
        trace: list[str] = []
        self.assertFalse(server.evaluate(cases[-1][0], empty, trace))
        for node, expect in cases[:-1]:
            trace = []
            self.assertEqual(server.evaluate(node, s, trace), expect, node)
            if expect and node["op"] != "exists":
                self.assertEqual(trace, [f"{node['op']}({node['field']})"])
        self.assertTrue(server.evaluate({"op": "not", "args": [cases[1][0]]}, s, []))
        self.assertFalse(server.evaluate({"op": "not", "args": [cases[0][0]]}, s, []))
        both = {"op": "any", "args": [
            {"op": "eq", "field": "operation", "value": "deploy"},
            {"op": "eq", "field": "subsystem", "value": "x"},
        ]}
        self.assertTrue(server.evaluate(both, s, []))
        first_false = {"op": "all", "args": [
            {"op": "eq", "field": "project", "value": "no"},
            {"op": "eq", "field": "subsystem", "value": "x"},
        ]}
        self.assertFalse(server.evaluate(first_false, s, []))
        deep = {"op": "exists", "field": "project"}
        for _ in range(4):
            deep = {"op": "not", "args": [deep]}
        with self.assertRaises(server.KBError) as e:
            server.validate_condition(deep)
        self.assertEqual(e.exception.code, "invalid_condition")
        wide = {"op": "all", "args": [{"op": "exists", "field": "project"} for _ in range(32)]}
        with self.assertRaises(server.KBError):
            server.validate_condition(wide)
        for bad in (
            {"op": "exists", "field": "project", "extra": 1},
            {"op": "touches_any", "field": "files_touched", "value": ["*.[ch]"]},
            {"op": "eq", "field": "services", "value": "node"},
            {"op": "all", "args": []},
            {"op": "nope"},
        ):
            with self.assertRaises(server.KBError) as e:
                server.validate_condition(bad)
            self.assertEqual(e.exception.code, "invalid_condition")
        via_tool = self.record(condition=deep)
        self.assertEqual(via_tool["error"]["code"], "invalid_condition")

    def test_error_hints_are_discoverable(self) -> None:
        # invalid_condition carries a one-line grammar example in fields.
        with self.assertRaises(server.KBError) as e:
            server.validate_condition({"op": "nope"})
        self.assertEqual(e.exception.code, "invalid_condition")
        hint = " ".join(e.exception.fields)
        self.assertIn('"op":"all"', hint)
        self.assertIn("touches_any", hint)
        via_tool = self.record(condition={"op": "eq", "field": "services", "value": "node"})
        self.assertEqual(via_tool["error"]["code"], "invalid_condition")
        self.assertTrue(any('"op":"all"' in f for f in via_tool["error"]["fields"]))
        # An invalid ChangeSummaryV1 lists the expected keys in fields.
        bad = server.preflight_check({"schema_version": 2, "project": PROJECT})
        self.assertEqual(bad["error"]["code"], "unsupported_schema")
        fields = " ".join(bad["error"]["fields"])
        for key in ("schema_version", "project", "services", "files_touched", "change_type"):
            self.assertIn(key, fields)
        bad2 = server.preflight_check({"schema_version": 1, "project": PROJECT, "services": "node",
                                       "files_touched": ["a.py"], "change_type": ["code"]})
        self.assertEqual(bad2["error"]["code"], "invalid_input")
        self.assertIn("empty_reason", " ".join(bad2["error"]["fields"]))

    def test_dependency_autosuggestion(self) -> None:
        cond = {"op": "all", "args": [
            {"op": "touches_any", "field": "files_touched", "value": ["deploy/compose.yaml"]},
            {"op": "touches_all", "field": "files_touched", "value": ["src/app.py", "deploy/*"]},
        ]}
        rec = self.record(proposed_invariant="auto deps", scope="auto", condition=cond)
        self.assertTrue(rec["ok"], rec)
        paths = json.loads(self.q("SELECT dependency_paths_json FROM rules WHERE id=?",
                                  (rec["rule_id"],))[0][0])
        self.assertEqual(paths, ["deploy/*", "deploy/compose.yaml", "src/app.py"])
        # Explicit dependency_paths win over the suggestion.
        rec2 = self.record(proposed_invariant="explicit deps", scope="explicit",
                           condition={"op": "touches_any", "field": "files_touched",
                                      "value": ["deploy/compose.yaml"]},
                           dependency_paths=["dep/pin.txt"])
        paths2 = json.loads(self.q("SELECT dependency_paths_json FROM rules WHERE id=?",
                                   (rec2["rule_id"],))[0][0])
        self.assertEqual(paths2, ["dep/pin.txt"])
        # Activation without dependency_paths keeps them and declares the
        # fingerprint, so the staleness mechanism works out of the box.
        (self.root / "deploy").mkdir()
        (self.root / "src").mkdir()
        (self.root / "deploy" / "compose.yaml").write_bytes(b"v1")
        (self.root / "src" / "app.py").write_bytes(b"v1")
        self.verify(rec["incident_id"], rec["rule_id"])
        act = self.activate(rec["rule_id"])
        self.assertTrue(act["ok"], act)
        self.assertEqual(json.loads(self.q("SELECT dependency_paths_json FROM rules WHERE id=?",
                                           (rec["rule_id"],))[0][0]),
                         ["deploy/*", "deploy/compose.yaml", "src/app.py"])
        self.assertIsNotNone(self.q("SELECT dependency_fingerprint FROM rules WHERE id=?",
                                    (rec["rule_id"],))[0][0])
        pf = server.preflight_check(self.summary(files_touched=["deploy/compose.yaml", "src/app.py"]))
        self.assertIn(rec["rule_id"], [m["rule_id"] for m in pf["matches"]])
        (self.root / "src" / "app.py").write_bytes(b"v2")
        pf = server.preflight_check(self.summary(files_touched=["deploy/compose.yaml", "src/app.py"]))
        self.assertIn(rec["rule_id"], [m["rule_id"] for m in pf["stale_matches"]])

    def test_recurrence_families(self) -> None:
        def bare(**kw: object) -> dict:
            return self.record(condition=None, proposed_invariant="", proposed_action="",
                               scope="", **kw)
        first = bare(title="Boot loop after flash", condition_hash="h-42")
        self.assertTrue(first["ok"], first)
        # Same (project, condition_hash): warn, but the call still succeeds.
        second = bare(title="unrelated wording", condition_hash="h-42")
        self.assertTrue(second["ok"], second)
        self.assertIn(f"possible recurrence of incident {first['incident_id']}", second["warnings"])
        # A near-identical title counts even without a shared hash.
        third = bare(title="boot loop after flash!")
        self.assertIn(f"possible recurrence of incident {first['incident_id']}", third["warnings"])
        # An unrelated incident does not warn.
        fourth = bare(title="Telemetry dashboard colors")
        self.assertFalse([w for w in fourth["warnings"] if "recurrence" in w], fourth["warnings"])
        # related_incidents lists the shared condition_hash family.
        detail = server.get_incident_details(second["incident_id"])
        self.assertEqual([r["id"] for r in detail["related_incidents"]],
                         [first["incident_id"]])
        for r in detail["related_incidents"]:
            self.assertEqual(set(r), {"id", "title", "status", "created_at", "resolution"})
            self.assertEqual(r["title"], "Boot loop after flash")
        # The section can be requested alone.
        only = server.get_incident_details(first["incident_id"], sections=["related_incidents"])
        self.assertEqual([r["id"] for r in only["related_incidents"]], [second["incident_id"]])
        self.assertNotIn("title", only)
        # No shared hash: an empty family, not an error.
        self.assertEqual(server.get_incident_details(third["incident_id"])["related_incidents"], [])

    def test_change_summary_contract(self) -> None:
        bad = server.preflight_check(self.summary(schema_version=2))
        self.assertEqual(bad["error"]["code"], "unsupported_schema")
        missing = server.preflight_check({"schema_version": 1, "project": PROJECT,
                                           "files_touched": ["a.py"], "change_type": ["code"]})
        self.assertEqual(missing["status"], "insufficient_context")
        self.assertIn("services", missing["missing_fields"])
        empty = server.preflight_check(self.summary(services=[]))
        self.assertNotEqual(empty["status"], "clear")
        self.assertIn("services", empty["missing_fields"])
        cleared = server.preflight_check(self.summary(services=[], empty_reason="no hay"))
        self.assertEqual(cleared["status"], "no_coverage")
        out, miss = server.normalize_summary(self.summary(files_touched=["./a", "a\\b"], services=["b", "a", "a"]))
        self.assertEqual(out["files_touched"], ["a", "a/b"])
        self.assertEqual(out["services"], ["a", "b"])
        self.assertEqual(miss, [])
        for path in ("../x", "/etc/passwd", "foo/../../etc"):
            r = server.preflight_check(self.summary(files_touched=[path]))
            self.assertEqual(r["error"]["code"], "invalid_input")
        self.assertEqual(server.preflight_check(self.summary(change_type=["nope"]))["error"]["code"],
                         "invalid_input")
        order = []
        for sev in ("info", "blocker", "warning"):
            rec = self.record(severity=sev, proposed_invariant=f"inv {sev}", proposed_action="x",
                              scope=sev)
            self.verify(rec["incident_id"], rec["rule_id"])
            self.activate(rec["rule_id"])
            order.append(rec["rule_id"])
        pf = server.preflight_check(self.summary())
        self.assertEqual([m["severity"] for m in pf["matches"]], ["blocker", "warning", "info"])
        rank = {"blocker": 0, "warning": 1, "info": 2}
        self.assertEqual(pf["matches"], sorted(pf["matches"], key=lambda m: (rank[m["severity"]], m["rule_id"])))
        self.assertEqual(server.preflight_check(self.summary())["matches"], pf["matches"])
        self.assertEqual(pf["next_tool"], "get_incident_details")
        before = self.q("SELECT COUNT(*) FROM incidents")[0][0]
        server.preflight_check(self.summary())
        self.assertEqual(self.q("SELECT COUNT(*) FROM incidents")[0][0], before)

    def test_verification_gate(self) -> None:
        for kw in (
            {"preconditions": {"db": "not_run"}},
            {"exercised_failing_path": False},
            {"method": "operator_review"},
            {"success_criterion": "  "},
        ):
            rec = self.record(proposed_invariant=f"inv {kw}")
            res = self.verify(rec["incident_id"], rec["rule_id"], **kw)
            self.assertFalse(res["effective_pass"])
            self.assertEqual(res["incident_status"], "open")
            self.assertEqual(res["rule_status"], "hypothesis")
            self.assertTrue(res["pending_requirements"])
        rec = self.record(proposed_invariant="la buena")
        ok = self.verify(rec["incident_id"], rec["rule_id"])
        self.assertTrue(ok["effective_pass"])
        self.assertEqual(ok["incident_status"], "verified_resolved")
        self.assertEqual(ok["rule_status"], "verified")
        self.q("UPDATE rules SET confidence=1 WHERE id=?", (rec["rule_id"],))
        fail = self.verify(rec["incident_id"], rec["rule_id"], verdict="fail")
        self.assertEqual(fail["incident_status"], "reopened")
        self.assertEqual(fail["rule_status"], "verified")
        conf = self.q("SELECT confidence FROM rules WHERE id=?", (rec["rule_id"],))[0][0]
        self.assertAlmostEqual(conf, 0.8)
        other = self.record(proposed_invariant="ajena")
        linked = self.verify(rec["incident_id"], other["rule_id"])
        self.assertEqual(linked["error"]["code"], "invalid_input")

    def test_rule_lifecycle(self) -> None:
        rec = self.record()
        rid = rec["rule_id"]
        allowed = set(server.RULE_TRANSITIONS)
        for src in STATUSES:
            for dst in STATUSES:
                try:
                    with server.tx() as (c, t):
                        c.execute("UPDATE rules SET status=? WHERE id=?", (src, rid))
                        server.transition(c, server.get_rule(c, rid), dst, "matriz", "test", t)
                    self.assertIn((src, dst), allowed)
                except server.KBError as e:
                    self.assertEqual(e.code, "illegal_transition")
                    self.assertNotIn((src, dst), allowed)
        self.q("UPDATE rules SET status='hypothesis', last_verified_at=NULL WHERE id=?", (rid,))
        self.assertEqual(self.activate(rid)["error"]["code"], "illegal_transition")
        self.clock.advance()
        self.assertEqual(self.verify(rec["incident_id"], rid)["rule_status"], "verified")
        past = "2020-01-01T00:00:00.000000+00:00"
        act = self.activate(rid, valid_until=past)
        self.assertEqual(act["status"], "active")
        self.assertEqual(act["revision"], 1)
        pf = server.preflight_check(self.summary())
        self.assertEqual(pf["matches"], [])
        self.assertEqual(pf["stale_matches"][0]["rule_id"], rid)
        self.assertEqual(pf["status"], "alert")
        self.assertEqual(self.q("SELECT stale_reason FROM rules WHERE id=?", (rid,))[0][0], "valid_until expired")
        self.assertEqual(self.activate(rid)["error"]["code"], "verification_required")
        self.clock.advance()
        self.assertEqual(self.verify(rec["incident_id"], rid)["rule_status"], "stale")
        again = self.activate(rid)
        self.assertEqual(again["revision"], 2)
        self.assertEqual(again["status"], "active")
        pin = Path("dep/pin.txt")
        pin.parent.mkdir()
        pin.write_bytes(b"v1")
        dep = self.record(proposed_invariant="depends on the pin", scope="deps",
                          condition={"op": "eq", "field": "project", "value": PROJECT})
        self.verify(dep["incident_id"], dep["rule_id"])
        self.activate(dep["rule_id"], dependency_paths=["./dep/pin.txt"])
        pin.write_bytes(b"v2")
        pf = server.preflight_check(self.summary())
        self.assertNotIn(dep["rule_id"], [m["rule_id"] for m in pf["matches"]])
        self.assertIn(dep["rule_id"], [m["rule_id"] for m in pf["stale_matches"]])
        self.assertEqual(self.q("SELECT stale_reason FROM rules WHERE id=?", (dep["rule_id"],))[0][0],
                         "dependencies changed")
        rev = self.record(proposed_invariant="review after", scope="rev")
        self.verify(rev["incident_id"], rev["rule_id"])
        self.activate(rev["rule_id"], review_after=past)
        server.list_active_invariants(PROJECT)
        status, reason = self.q("SELECT status, stale_reason FROM rules WHERE id=?", (rev["rule_id"],))[0]
        self.assertEqual((status, reason), ("stale", "review_after expired"))
        gone = self.record(proposed_invariant="will deprecate", scope="old")
        self.verify(gone["incident_id"], gone["rule_id"])
        self.activate(gone["rule_id"])
        self.assertEqual(server.deprecate_rule(gone["rule_id"], "obsolete", "ana")["status"], "deprecated")
        self.assertEqual(server.deprecate_rule(gone["rule_id"], "again", "ana")["error"]["code"],
                         "illegal_transition")
        compiled = json.loads(server.compile_artifacts(PROJECT)["files"] and
                              (server.ARTIFACT_DIR / "invariants.json").read_text())
        ids = {r["id"] for r in compiled["rules"]}
        self.assertNotIn(gone["rule_id"], ids)
        self.assertTrue(self.q("SELECT COUNT(*) FROM rule_transitions WHERE rule_id=?", (rid,))[0][0] >= 4)

    def test_tools_compile_and_list(self) -> None:
        self.assertEqual(self.activate("R-missing")["error"]["code"], "not_found")
        self.assertEqual(server.activate_rule("x", "", "porque")["error"]["code"], "invalid_input")
        bare = server.compile_artifacts(PROJECT, write=False)
        self.assertFalse(bare["written"])
        self.assertEqual(bare["files"], [])
        self.assertFalse(server.ARTIFACT_DIR.exists())
        a = self.record(scope="zeta")
        b = self.record(scope="alpha", proposed_invariant="segunda", severity="info")
        for rec in (a, b):
            self.verify(rec["incident_id"], rec["rule_id"])
            self.activate(rec["rule_id"])
        out = server.compile_artifacts(PROJECT)
        self.assertEqual(out["files"], ["invariants.json", "active_rules.md"])
        self.assertEqual(list(server.ARTIFACT_DIR.rglob("*.tmp")), [])
        listed = server.list_active_invariants(PROJECT, limit=1)
        self.assertEqual([r["scope"] for r in server.list_active_invariants(PROJECT)["rules"]], ["alpha", "zeta"])
        self.assertEqual(listed["count"], 2)
        self.assertTrue(listed["truncated"])
        self.assertEqual(listed["total_active"], 2)
        self.assertEqual(listed["artifact_sha256"], out["artifact_sha256"])
        only = server.list_active_invariants(PROJECT, scope="alpha", severity="info")
        self.assertEqual(only["count"], 1)
        incomplete = server.record_failure(project=PROJECT, title="t", symptom="s", proposed_invariant="solo")
        self.assertEqual(incomplete["error"]["code"], "invalid_input")
        huge = server.record_failure(project=PROJECT, title="x" * 241, symptom="s")
        self.assertEqual(huge["error"]["code"], "too_large")
        dup = self.record(scope="zeta")
        self.assertEqual(dup["error"]["code"], "conflict")

    def test_idempotency(self) -> None:
        kw = dict(idempotency_key="k1")
        first = self.record(**kw)
        second = self.record(**kw)
        self.assertEqual(first, second)
        self.assertEqual(self.q("SELECT COUNT(*) FROM incidents")[0][0], 1)
        self.assertEqual(self.q("SELECT COUNT(*) FROM idempotency_keys")[0][0], 1)
        clash = self.record(symptom="otro", **kw)
        self.assertEqual(clash["error"]["code"], "idempotency_conflict")
        self.assertEqual(self.q("SELECT COUNT(*) FROM incidents")[0][0], 1)

    def test_secrets(self) -> None:
        self.assertEqual(set(SECRETS), {k for k, _ in server.SECRET_PATTERNS})
        for kind, secret in SECRETS.items():
            text, found = server.redact(f"before {secret} after")
            self.assertEqual(found, [kind], kind)
            self.assertNotIn(secret, text)
            again, found2 = server.redact(text)
            self.assertEqual(again, text)
            self.assertEqual(found2, [])
            rec = self.record(title=f"t {kind}", symptom=f"before {secret} after",
                              proposed_invariant=f"inv {kind}", proposed_action="x", scope=kind)
            self.assertTrue(rec["ok"], rec)
            self.assertTrue(any(f"redacted {kind}" in w for w in rec["warnings"]))
            blob = " ".join(rec["warnings"])
            self.assertNotIn(secret, blob)
            detail = server.get_incident_details(rec["incident_id"])
            dumped = json.dumps(detail, ensure_ascii=False)
            self.assertNotIn(secret, dumped)
            self.assertEqual(detail["sensitivity"], "redacted")
            for path in server.KB_DIR.iterdir():
                self.assertNotIn(secret.encode(), path.read_bytes(), kind)
            art = server.compile_artifacts(PROJECT)
            if art["written"]:
                for path in server.ARTIFACT_DIR.iterdir():
                    self.assertNotIn(secret.encode(), path.read_bytes(), kind)
        noisy = self.record(symptom=f"saw {ENTROPY} in the log", proposed_invariant="entropy",
                            proposed_action="x", scope="entropy")
        self.assertTrue(any("high-entropy" in w for w in noisy["warnings"]))
        self.assertNotIn(ENTROPY, " ".join(noisy["warnings"]))
        self.assertEqual(noisy["ok"] and self.q(
            "SELECT sensitivity FROM incidents WHERE id=?", (noisy["incident_id"],))[0][0], "normal")
        detail = server.get_incident_details(noisy["incident_id"])
        self.assertIn(ENTROPY, detail["symptom"])
        locked = self.record(symptom="visible", error_code="E1", proposed_invariant="restringida",
                             proposed_action="x", scope="restricted")
        self.q("UPDATE incidents SET sensitivity='restricted' WHERE id=?", (locked["incident_id"],))
        hidden = server.get_incident_details(locked["incident_id"])
        self.assertEqual(hidden["title"], "titulo")
        self.assertEqual(hidden["error_code"], "E1")
        self.assertEqual(hidden["symptom"], "[RESTRICTED]")
        self.assertNotIn("visible", json.dumps(hidden))
        missing = server.get_incident_details("no-such")
        self.assertEqual(missing["error"]["code"], "not_found")
        self.assertNotIn(locked["incident_id"], json.dumps(missing))
        bad_sec = server.get_incident_details(locked["incident_id"], sections=["nope"])
        self.assertEqual(bad_sec["error"]["code"], "invalid_input")

    def test_entropy_allowlist(self) -> None:
        # 0x addresses, git hashes, and sha256:/md5: digests are technical
        # tokens: no entropy warning, no echo problem.
        digest = "0123456789abcdef" * 4  # 64 hex chars
        git_hash = "0123456789abcdef" * 2  # 32 hex chars
        tokens = [
            "fault at 0x0304F298 then 0x0304F298deadbeef",
            f"fixed in {git_hash} and again in 0304f298",
            f"sha256:{digest}",
            f"md5:{git_hash}",
        ]
        for text in tokens:
            self.assertEqual(server.low_confidence_candidates(text), 0, text)
            rec = self.record(symptom=text, condition=None, proposed_invariant="",
                              proposed_action="", scope="")
            self.assertTrue(rec["ok"], rec)
            self.assertFalse(any("high-entropy" in w for w in rec["warnings"]),
                             (text, rec["warnings"]))
        # Real high-entropy strings still warn, and real secrets still redact.
        self.assertGreaterEqual(server.low_confidence_candidates(ENTROPY), 1)
        leaky = self.record(symptom=f"key ghp_{'a' * 36} and {ENTROPY}",
                            proposed_invariant="still noisy", proposed_action="x", scope="noisy")
        self.assertTrue(any("high-entropy" in w for w in leaky["warnings"]))
        self.assertTrue(any("redacted github_token" in w for w in leaky["warnings"]))
        self.assertNotIn("ghp_", json.dumps(leaky))

    def test_internal_error_is_opaque(self) -> None:
        orig = server.tx
        def boom():
            raise RuntimeError("TRACEBACK /var/secret SELECT * FROM passwords")
        server.tx = boom  # type: ignore[assignment]
        try:
            r = server.record_failure(project=PROJECT, title="t", symptom="s")
        finally:
            server.tx = orig
        self.assertEqual(r["error"]["code"], "internal")
        blob = json.dumps(r)
        for leaked in ("TRACEBACK", "secret", "SELECT", "Traceback"):
            self.assertNotIn(leaked, blob)

    def test_end_to_end_without_network(self) -> None:
        real = socket.socket
        def guard(*_a, **_k):
            raise Net("network")
        socket.socket = guard  # type: ignore[assignment]
        try:
            rec = self.record()
            self.assertEqual(self.verify(rec["incident_id"], rec["rule_id"])["rule_status"], "verified")
            pin = Path("dep/pin.txt")
            pin.parent.mkdir(exist_ok=True)
            pin.write_bytes(b"v1")
            self.activate(rec["rule_id"], dependency_paths=["dep/pin.txt"])
            alert = server.preflight_check(self.summary())
            self.assertEqual(alert["status"], "alert")
            self.assertEqual(alert["matches"][0]["rule_id"], rec["rule_id"])
            h1 = server.compile_artifacts(PROJECT)["artifact_sha256"]
            h2 = server.compile_artifacts(PROJECT)["artifact_sha256"]
            self.assertEqual(h1, h2)
            pin.write_bytes(b"v2")
            stale = server.preflight_check(self.summary())
            self.assertEqual(stale["matches"], [])
            self.assertEqual(stale["stale_matches"][0]["rule_id"], rec["rule_id"])
            self.assertEqual(server.deprecate_rule(rec["rule_id"], "no longer", "ana")["status"], "deprecated")
            compiled = server.compile_artifacts(PROJECT)
            self.assertEqual(compiled["rule_count"], 0)
            self.assertNotIn(rec["rule_id"], (server.ARTIFACT_DIR / "invariants.json").read_text())
        finally:
            socket.socket = real

    def test_gaps(self) -> None:
        bare = server.preflight_check(self.summary())
        self.assertEqual(bare["status"], "no_coverage")
        self.assertEqual(bare["evaluated"], 0)
        miss = self.record(condition={"op": "eq", "field": "project", "value": "otro"},
                           proposed_invariant="no coincide", scope="miss")
        self.verify(miss["incident_id"], miss["rule_id"])
        self.activate(miss["rule_id"])
        quiet = server.preflight_check(self.summary())
        self.assertEqual(quiet["status"], "clear")
        self.assertEqual(quiet["matches"], [])
        self.record(proposed_invariant="recaida", scope="later",
                    condition={"op": "eq", "field": "project", "value": "otro"})
        stats = server.preflight_stats(PROJECT)
        self.assertGreaterEqual(stats["recurred_after"].get("clear", 0), 1)
        self.assertGreaterEqual(stats["recurred_after"].get("no_coverage", 0), 1)
        hyp = self.record(proposed_invariant="todavia hipotesis", scope="hip")
        soft = server.preflight_check(self.summary())
        self.assertEqual(soft["matches"], [])
        self.assertEqual(soft["status"], "alert")
        self.assertEqual(soft["hypothesis_matches"][0]["rule_id"], hyp["rule_id"])
        self.assertEqual(soft["hypothesis_matches"][0]["severity"], "info")
        near = self.record(
            proposed_invariant="el yaml de al lado", scope="near",
            condition={"op": "touches_any", "field": "files_touched", "value": ["deploy/a.yaml"]},
        )
        coded = self.record(
            proposed_invariant="code from the diff", scope="code",
            condition={"op": "any_in", "field": "change_type", "value": ["code"]},
        )
        self.verify(coded["incident_id"], coded["rule_id"])
        self.activate(coded["rule_id"])
        fam = self.record(
            proposed_invariant="error family", scope="err",
            condition={"op": "eq", "field": "error_code", "value": "ERR_CONN_RESET"},
        )
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
        subprocess.run(["git", "init"], cwd=self.root, check=True, capture_output=True)
        (self.root / "src").mkdir()
        (self.root / "deploy").mkdir()
        (self.root / "src" / "app.py").write_text("x\n")
        (self.root / "deploy" / "a.yaml").write_text("a\n")
        subprocess.run(["git", "add", "-A"], cwd=self.root, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=self.root, check=True,
                       capture_output=True, env=env)
        (self.root / "src" / "app.py").write_text("y\n")
        (self.root / "deploy" / "b.yaml").write_text("b\n")
        pf = server.preflight_check(self.summary(files_touched=["README.md"], change_type=["docs"],
                                                 error_code="ERR_CONN_TIMEOUT"))
        self.assertIn("src/app.py", pf["git_files"])
        self.assertIn("deploy/b.yaml", pf["git_files"])
        self.assertIn(coded["rule_id"], [m["rule_id"] for m in pf["matches"]])
        self.assertEqual(next(m["note"] for m in pf["variant_matches"] if m["rule_id"] == near["rule_id"]),
                         "same directory")
        self.assertIn(fam["rule_id"], [m["rule_id"] for m in pf["variant_matches"]])
        self.assertEqual(next(m["note"] for m in pf["variant_matches"] if m["rule_id"] == fam["rule_id"]),
                         "related error_code")
        self.assertNotIn(near["rule_id"], [m["rule_id"] for m in pf["matches"]])

    def test_stdio_startup(self) -> None:
        kb = self.root / "stdio-kb"
        art = self.root / "stdio-art"
        asyncio.run(asyncio.wait_for(self._stdio(kb, art), 20))
        con = sqlite3.connect(kb / "kb.sqlite3")
        try:
            self.assertEqual(con.execute("PRAGMA user_version").fetchone()[0], 2)
        finally:
            con.close()

    async def _stdio(self, kb: Path, art: Path) -> None:
        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        params = StdioServerParameters(
            command=sys.executable,
            args=[str(Path(__file__).resolve().parent / "server.py")],
            cwd=str(self.root),
            env={"FAILURE_KB_DIR": str(kb), "FAILURE_KB_ARTIFACTS": str(art)},
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                listed = await session.list_tools()
                names = sorted(t.name for t in listed.tools)
                self.assertEqual(names, [
                    "activate_rule", "compile_artifacts", "deprecate_rule", "get_incident_details",
                    "list_active_invariants", "preflight_check", "preflight_stats",
                    "record_failure", "verify_resolution",
                ])
                schema = next(t for t in listed.tools if t.name == "record_failure").inputSchema
                self.assertIn("project", schema["properties"])
                result = await session.call_tool("record_failure", {
                    "project": "stdio", "title": "t", "symptom": "s",
                })
                data = json.loads(result.content[0].text)
                self.assertTrue(data["ok"])
                self.assertEqual(data["status"], "open")
                self.assertIsNone(data["rule_id"])


if __name__ == "__main__":
    unittest.main()
