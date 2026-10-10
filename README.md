# DFIU (Don't F*ck It Up)

Local knowledge base for failures you have already paid for. An agent records an incident, a human verifies that the fix actually works, and only then does someone promote the lesson to an active invariant. Before the next risky change, `preflight_check` evaluates those invariants against a short change summary and the git diff in the working tree.

DFIU is a single-process [MCP](https://modelcontextprotocol.io) server. It speaks stdio, stores everything in SQLite, and does not open a socket, call a model, or apply a fix. Detection stays cheap. The long write-up of an incident is fetched later, by id, and only if something matched.

The contract lives in [`mcp_failure_preflight_spec_v2.md`](mcp_failure_preflight_spec_v2.md). This repository is the MVP of sections 1–12 of that spec: one module, [`server.py`](server.py), version 2.0.0.

## What it is for

A preflight should answer one question: *have we already broken this exact kind of change?* The answer is a compact status, not a dump of old logs.

- Known, reviewed failures become rules the agent cannot quietly skip.
- Unverified guesses stay visible as hypotheses. They warn. They do not block.
- Rules that depend on a file, or that have passed their review date, go stale instead of pretending they are still true.
- Secrets from a fixed catalog are stripped before text is stored or returned.

Out of scope, on purpose: automatic diagnosis, autonomous repair, conversation ingestion, embeddings, and any tool that flashes hardware, runs Docker, or talks to an external database.

## How a failure becomes a check

```
record_failure          incident = open
        │               optional rule = hypothesis
        ▼
verify_resolution       pass with real evidence
        │               incident = verified_resolved
        │               linked rule = verified
        ▼
activate_rule           a named reviewer promotes it
        │               rule = active
        ▼
preflight_check         active rules can alert
compile_artifacts       active rules only, written to disk
```

A later `fail` reopens the incident and lowers the linked rule's confidence by 0.2. It does not deactivate the rule. Refuting a rule is `deprecate_rule`, with a reason and a reviewer. History is append-only: verification rows and rule transitions are never deleted.

| Incident status | Meaning |
| --- | --- |
| `open` | Recorded. No effective verification yet. |
| `change_applied_unverified` | A change was applied. Still not verified. The client sets this; the MVP does not. |
| `verified_resolved` | At least one effective pass. The only status that means "fixed". |
| `reopened` | A `fail` arrived after `verified_resolved`. Earlier evidence stays. |
| `closed` | Administrative close. Not produced automatically. |

| Rule status | Seen by preflight | Written to artifacts |
| --- | --- | --- |
| `hypothesis` | Yes, as `hypothesis_matches`, severity `info`. Does not block. | No |
| `verified` | Same as `hypothesis`, until someone activates it. | No |
| `active` | Yes, as `matches`. This is what can block. | Yes |
| `stale` | Yes, as `stale_matches`. Asks for revalidation. Never a silent `clear`, never a block. | No |
| `deprecated` | No | No |

An effective pass is stricter than a green checkbox. All of these have to be true:

- `verdict` is `pass`
- every precondition is `pass`
- `exercised_failing_path` is true (the test actually hit the path that failed)
- `success_criterion` was written before the test and is non-empty
- `method` is `test`, `reproduction`, or `regression` — not `operator_review`

Anything weaker is stored, and `pending_requirements` says what is still missing. States do not move.

## Tools

Nine tools. Success is `{"ok": true, ...}`. Failure is `{"ok": false, "error": {"code", "message", "fields"}}` and never includes a traceback, a filesystem path, or SQL.

| Tool | What it does |
| --- | --- |
| `record_failure` | Opens an incident. If you also send a proposed invariant, you must send the action, the condition, and the scope; that creates a `hypothesis` rule linked to the incident. |
| `verify_resolution` | Appends a verification. An effective pass resolves the incident and moves a linked hypothesis to `verified`. It never activates a rule. |
| `activate_rule` | `verified` or `stale` → `active`. Requires `reviewer` and `reason`. From `stale`, there must be an effective verification newer than the stale transition, and `revision` increments. |
| `deprecate_rule` | Any non-deprecated status → `deprecated`. Requires `reviewer` and `reason`. |
| `preflight_check` | Evaluates a `ChangeSummaryV1` plus the git diff. Returns matches, hypotheses, stale rules, and near-miss variants. |
| `preflight_stats` | Counts preflights for a project, and how many were later followed by `record_failure` (`recurred`). |
| `compile_artifacts` | Refreshes staleness, then writes canonical `invariants.json` and derived `active_rules.md`. |
| `list_active_invariants` | Compact inventory of active rules. Optional `scope` and `severity` filters. |
| `get_incident_details` | One incident, by exact id, in bounded sections. Text is redacted again on the way out. |

`record_failure` and `verify_resolution` accept `idempotency_key`. The same key and the same request replay the stored response. The same key with a different request returns `idempotency_conflict`.

Every `preflight_check` is appended to `preflight_log`. The next `record_failure` for that project marks still-open rows `recurred`, which is what `preflight_stats` reports. The check itself does not store the raw summary beyond a hash, the file list, and the rule ids that participated.

### Preflight status

Evaluated in this order:

1. **`alert`** — at least one active match, hypothesis, stale rule, or variant.
2. **`insufficient_context`** — a required field was missing or empty, or a condition needed a field the summary did not have.
3. **`no_coverage`** — nothing evaluable exists for this project. An empty rule set is never `clear`.
4. **`clear`** — rules were evaluated and none of them matched.

`matches` are ordered by severity (`blocker`, `warning`, `info`) and then by rule id. Each match carries up to three linked incident ids. `next_tool` is `get_incident_details` when anything was heard, so the agent can pull the write-up without having received it up front.

### Change summary

`preflight_check` takes one object, `ChangeSummaryV1`:

| Field | Required | Notes |
| --- | --- | --- |
| `schema_version` | yes | Must be `1`. Anything else is `unsupported_schema`. |
| `project` | yes | Rules are filtered by project. |
| `services` | yes | Sorted, de-duplicated. At most 200 strings. |
| `files_touched` | yes | Relative POSIX paths. No `..`, no absolute paths. |
| `change_type` | yes | One or more of `code`, `config`, `dependency`, `schema`, `infra`, `firmware`, `docs`, `test`. |
| `environment_tags` | no | Sorted, de-duplicated. |
| `operation`, `subsystem`, `error_code`, `revision` | no | `revision` is a git sha, or the explicit string `"unknown"`. |
| `empty_reason` | conditional | Required when a required list above is present but empty. |

When the process cwd is the git work-tree root, DFIU unions `files_touched` and `change_type` with `git diff`, the index, and untracked files. The agent can add paths. It cannot omit paths that git already shows. If cwd is not that root, git is ignored and the summary stands alone.

```json
{
  "schema_version": 1,
  "project": "pterodactyl",
  "services": ["node"],
  "files_touched": ["deploy/compose.yaml"],
  "change_type": ["config"],
  "operation": "deploy",
  "environment_tags": ["docker"],
  "revision": "abc123"
}
```

### Conditions

A rule's `condition` is a closed JSON tree. It is validated when the rule is created and never executed as code. Depth is at most 4. Node count is at most 32.

```
{"op": "all"|"any", "args": [Node, ...]}
{"op": "not", "args": [Node]}
{"op": "exists", "field": "<field>"}
{"op": "eq"|"prefix", "field": "<scalar>", "value": "<string>"}
{"op": "in", "field": "<scalar>", "value": ["<string>", ...]}
{"op": "any_in", "field": "<list>", "value": ["<string>", ...]}
{"op": "touches_any"|"touches_all", "field": "files_touched", "value": ["<glob>", ...]}
```

Scalars are `project`, `operation`, `subsystem`, `error_code`, `revision`. Lists are `services`, `files_touched`, `change_type`, `environment_tags`. Globs are `fnmatch` (`*`, `?`) and character classes are rejected. `touches_any` means some file matches some glob. `touches_all` means every glob matches at least one file. A missing field on a leaf other than `exists` makes that rule `insufficient_context` and adds the field to `missing_fields`. `all` stops at the first false. `any` is true if one branch matches, even when another branch is missing its field.

A variant is a near miss: same directory family, or the same `error_code` family, without a full match. Variants are reported. They do not block.

### Staleness

`preflight_check`, `list_active_invariants`, and `compile_artifacts` refresh staleness first. An active rule becomes `stale` when `valid_until` or `review_after` has passed, or when the `dependency_fingerprint` no longer matches.

The fingerprint is declared at activation as a list of repo-relative files. It is the sha256 of each normalized path plus the sha256 of that file's bytes (`MISSING` if the file is gone), in sorted order. A rule with no dependency paths only expires by date.

### Artifacts

`compile_artifacts` writes two files under `FAILURE_KB_ARTIFACTS` (default `.failure-kb/artifacts`):

- `invariants.json` — canonical. Sorted keys, two-space indent, UTF-8, LF, trailing newline. No timestamp. `artifact_sha256` is the sha256 of those exact bytes. Rules are ordered by `scope`, then `id`.
- `active_rules.md` — one line per rule: `- [severity] `id` (scope): invariant -> action`.

Only `active` rules are compiled. Pass `write: false` to compute the hash without touching disk. Writes are a temp file, `fsync`, then `os.replace`.

## Secrets

Free text is scrubbed before it is stored, and `get_incident_details` redacts again on output. High-confidence matches become `[REDACTED:secret:<kind>]`. The catalog covers private keys, AWS access keys, GitHub and Slack tokens, OpenAI-like and Google API keys, JWTs, `Authorization` headers, URLs with embedded credentials, and assignments whose name looks like a password, secret, token, or API key.

High-entropy strings (Shannon entropy ≥ 4.0 bits/character, length ≥ 20) are not rewritten. The response carries a warning and does not echo the candidate. If anything was redacted, the incident's `sensitivity` is `redacted`. A `restricted` incident is supposed to return only `title`, `status`, and `error_code`.

## Layout and storage

```
server.py                          the server
test_mvp.py                        unittest suite
mcp_failure_preflight_spec_v2.md   the contract
requirements.txt                   mcp==1.30.0
requirements.lock                  same pin, for the reason below
```

SQLite lives at `$FAILURE_KB_DIR/kb.sqlite3` (default `.failure-kb/kb.sqlite3`). The directory is mode `0700`, the database file `0600`. Connections use `foreign_keys=ON`, `journal_mode=WAL`, and `busy_timeout=5000`. Each write takes one connection and one `BEGIN IMMEDIATE`, stamps every row with a single UTC timestamp, and closes the connection when it finishes. Schema changes are ordered SQL strings applied through `PRAGMA user_version`.

| Variable | Default | Role |
| --- | --- | --- |
| `FAILURE_KB_DIR` | `.failure-kb` | Database directory. Relative paths follow the process cwd. |
| `FAILURE_KB_ARTIFACTS` | `.failure-kb/artifacts` | Fixed output directory. The model never chooses this path. |

**Git policy B** (this repo): `.failure-kb/` is gitignored, database included. Artifacts are regenerated with `compile_artifacts`. The database is never committed. Policy A (version the two artifact files and fail CI on drift) is described in the spec and is not what this tree does.

## Run it

Python 3.11 or newer. The `mcp` package is pinned to 1.30.0 because mcp 2.x renamed FastMCP; `requirements.lock` is that pin.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python server.py
```

`server.py` migrates, then serves stdio. If you run it in a terminal you will see nothing useful: the client owns stdin. Point the MCP client at the venv interpreter and set the working directory to the project whose diff should be read. Example for Cursor (`.cursor/mcp.json`), with paths adjusted:

```json
{
  "mcpServers": {
    "dfiu": {
      "command": "/absolute/path/to/dfiu/.venv/bin/python",
      "args": ["/absolute/path/to/dfiu/server.py"]
    }
  }
}
```

A typical agent loop:

1. `preflight_check` with a `ChangeSummaryV1` before a deploy, a schema change, or a firmware flash.
2. On `alert`, call `get_incident_details` for the ids in the match. Do not treat `hypothesis_matches` as a block.
3. After a failure in the wild, `record_failure`. If you already know the invariant, include `proposed_invariant`, `proposed_action`, `condition`, and `scope`.
4. `verify_resolution` once a real test exercises the old failure.
5. `activate_rule` when a reviewer is willing to put their name on it.
6. `compile_artifacts` so the JSON and Markdown match the database.

## Tests

```bash
.venv/bin/python -m unittest test_mvp
```

`test_mvp.py` walks the happy path: record, verify, activate, preflight, artifacts, idempotency, and the git-union behavior on ASCII paths. It does not cover the gaps below.

## Contract vs. this tree

`server.py` is the source of truth where it deliberately departs from the spec's reference block:

1. Zero evaluable rules returns `no_coverage`, never `clear`.
2. `files_touched` and `change_type` are unioned with the git diff of the cwd, and only when cwd is the work-tree root. A parent repo is not adopted.
3. `hypothesis` and `verified` come back as `hypothesis_matches` at severity `info` and do not block.
4. The same directory, or the same `error_code` family, comes back as `variant_matches`.
5. Each preflight is logged. `record_failure` marks those rows `recurred`. `preflight_stats` returns the counts.

[`dfiu-cli-design.md`](dfiu-cli-design.md) is a sketch for a future `dfiu` command (install, project discovery, git hooks). None of that is implemented. Today the product is `python server.py`.
