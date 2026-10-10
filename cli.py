# cli.py — dfiu command: serve over stdio, install into agent configs.
from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

AGENTS = ("cursor", "claude", "codex", "kiro", "commandcode")

# Words that make a commit look failure-related. Word match, case-insensitive.
FAILURE_WORDS = (
    "fix", "fixed", "fixes", "fixing", "hotfix", "bugfix", "revert", "reverted", "reverts",
    "brick", "bricked", "bricking", "crash", "crashes", "crashed", "crashing",
    "wrong", "broken", "bug", "bugs", "regression", "fail", "fails", "failed", "failure",
    "fault", "error", "errors", "segfault", "panic", "deadlock", "corrupt", "corrupted",
    "corruption", "hang", "hangs", "freeze", "leak", "leaks", "oops", "wipe", "wiped",
    "data loss",
)
FAILURE_RE = re.compile(r"\b(?:" + "|".join(FAILURE_WORDS) + r")\b", re.IGNORECASE)
RECALL_SCAN_COMMITS = 2000


class ConfigError(Exception):
    pass


def version() -> str:
    try:
        return importlib.metadata.version("dfiu")
    except importlib.metadata.PackageNotFoundError:
        return "2.0.0"


def command_path() -> str:
    exe = Path(sys.argv[0]).resolve()
    if exe.name == "dfiu":
        return str(exe)
    found = shutil.which("dfiu")
    return found or "dfiu"


def entry_args(agent: str) -> list[str]:
    # Cursor does not always use the workspace as cwd. The client expands the variable.
    if agent == "cursor":
        return ["serve", "--project", "${workspaceFolder}"]
    return ["serve"]


def json_entry(command: str, args: list[str]) -> dict:
    return {"type": "stdio", "command": command, "args": args}


def agent_entry(agent: str, command: str, location: str) -> dict:
    args = entry_args(agent)
    if agent == "kiro":
        return {"command": command, "args": args, "disabled": False}
    # Command Code's project file is also .mcp.json. Same object, either writer.
    if agent == "commandcode" or (agent == "claude" and location == "local"):
        return {"type": "stdio", "transport": "stdio", "command": command, "args": args}
    return json_entry(command, args)


def load_json_config(text: str) -> dict:
    if not text.strip():
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ConfigError(f"invalid JSON ({e})") from e
    if not isinstance(data, dict):
        raise ConfigError("JSON root must be an object")
    servers = data.get("mcpServers")
    if servers is not None and not isinstance(servers, dict):
        raise ConfigError("mcpServers must be an object")
    return data


def dump_json(data: dict) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def upsert_mcp_json(text: str, entry: dict) -> str:
    data = load_json_config(text)
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        servers = {}
        data["mcpServers"] = servers
    servers["dfiu"] = entry
    return dump_json(data)


def remove_mcp_json(text: str) -> str:
    data = load_json_config(text)
    servers = data.get("mcpServers")
    if isinstance(servers, dict):
        servers.pop("dfiu", None)
    return dump_json(data)


def json_has_dfiu(text: str) -> bool:
    servers = load_json_config(text).get("mcpServers")
    return isinstance(servers, dict) and "dfiu" in servers


def table_name(line: str) -> str | None:
    s = line.strip()
    if len(s) < 3 or not s.startswith("[") or not s.endswith("]") or s.startswith("[["):
        return None
    return s[1:-1].strip().strip('"')


def is_dfiu_table(name: str) -> bool:
    return name == "mcp_servers.dfiu" or name.startswith("mcp_servers.dfiu.")


def toml_has_dfiu(text: str) -> bool:
    return any(is_dfiu_table(n) for line in text.splitlines() if (n := table_name(line)))


def remove_codex_toml(text: str) -> str:
    out: list[str] = []
    skipping = False
    for line in text.splitlines(keepends=True):
        name = table_name(line)
        if name is not None:
            skipping = is_dfiu_table(name)
        if not skipping:
            out.append(line)
    return "".join(out)


def toml_block(command: str, args: list[str]) -> str:
    rendered = ", ".join(json.dumps(a) for a in args)
    return f'[mcp_servers.dfiu]\ncommand = {json.dumps(command)}\nargs = [{rendered}]\n'


def upsert_codex_toml(text: str, command: str, args: list[str]) -> str:
    base = remove_codex_toml(text).rstrip()
    block = toml_block(command, args)
    if not base:
        return block
    return base + "\n\n" + block


def config_path(agent: str, location: str, home: Path, root: Path) -> Path:
    if location == "global":
        return {
            "cursor": home / ".cursor" / "mcp.json",
            "claude": home / ".claude.json",
            "codex": home / ".codex" / "config.toml",
            "kiro": home / ".kiro" / "settings" / "mcp.json",
            "commandcode": home / ".commandcode" / "mcp.json",
        }[agent]
    return {
        "cursor": root / ".cursor" / "mcp.json",
        "claude": root / ".mcp.json",
        "codex": root / ".codex" / "config.toml",
        "kiro": root / ".kiro" / "settings" / "mcp.json",
        "commandcode": root / ".mcp.json",
    }[agent]


def detected(home: Path) -> list[str]:
    found: list[str] = []
    if (home / ".cursor").is_dir():
        found.append("cursor")
    if (home / ".claude.json").is_file() or (home / ".claude").is_dir():
        found.append("claude")
    if (home / ".codex").is_dir():
        found.append("codex")
    if (home / ".kiro").is_dir():
        found.append("kiro")
    if (home / ".commandcode").is_dir():
        found.append("commandcode")
    return found


def select_agents(spec: str, home: Path) -> list[str]:
    spec = spec.strip().lower()
    if spec == "auto":
        return detected(home)
    if spec == "all":
        return list(AGENTS)
    names = [p.strip() for p in spec.split(",") if p.strip()]
    bad = [n for n in names if n not in AGENTS]
    if bad or not names:
        raise ConfigError(f"unknown target: {', '.join(bad) or spec}")
    return list(dict.fromkeys(names))


def snippet(agent: str, command: str) -> str:
    if agent == "codex":
        return toml_block(command, entry_args(agent))
    return dump_json({"mcpServers": {"dfiu": agent_entry(agent, command, "global")}})


def write_if_changed(path: Path, text: str) -> str:
    old = path.read_text(encoding="utf-8") if path.exists() else None
    if old == text:
        return "unchanged"
    path.parent.mkdir(parents=True, exist_ok=True)
    if old is not None:
        bak = path.with_name(path.name + ".dfiu.bak")
        bak.write_text(old, encoding="utf-8")
        os.chmod(bak, 0o600)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.chmod(tmp, path.stat().st_mode & 0o777 if path.exists() else 0o600)
    os.replace(tmp, path)
    return "updated"


def apply_install(path: Path, agent: str, command: str, refresh: bool, location: str = "global") -> str:
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    if agent == "codex":
        if refresh and not toml_has_dfiu(text):
            return "skipped"
        new = upsert_codex_toml(text, command, entry_args(agent))
    else:
        if refresh and not json_has_dfiu(text):
            return "skipped"
        new = upsert_mcp_json(text, agent_entry(agent, command, location))
    return write_if_changed(path, new)


def apply_uninstall(path: Path, agent: str) -> str:
    if not path.exists():
        return "absent"
    text = path.read_text(encoding="utf-8")
    if agent == "codex":
        if not toml_has_dfiu(text):
            return "absent"
        new = remove_codex_toml(text)
        if new.strip() and not new.endswith("\n"):
            new += "\n"
    else:
        if not json_has_dfiu(text):
            return "absent"
        new = remove_mcp_json(text)
    return write_if_changed(path, new)


def serve_project(project: str, is_tty: bool) -> Path | None:
    """None: stdin is a terminal, so do not start the protocol. Otherwise the cwd to use."""
    if is_tty:
        return None
    if not project:
        return Path.cwd()
    root = Path(project).expanduser()
    if not root.is_dir():
        raise ConfigError(f"not a directory: {project}")
    return root.resolve()


def serve(project: str) -> int:
    root = serve_project(project, sys.stdin.isatty())
    if root is None:
        print(
            "dfiu serve speaks MCP over stdio. The editor starts it.\n"
            "Register it with: dfiu install",
            file=sys.stderr,
        )
        return 0
    os.chdir(root)
    from server import mcp, migrate

    migrate()
    mcp.run(transport="stdio")
    return 0


def git_log_failures(root: Path, limit: int) -> list[dict]:
    """Scan git log for failure-indicating commits. Reads the repo, writes nothing."""
    env = os.environ.copy()
    for var in ("GIT_DIR", "GIT_WORK_TREE"):
        env.pop(var, None)
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "log", f"-n{RECALL_SCAN_COMMITS}", "--no-merges",
             "--format=%H%x1f%s%x1f%b%x1e"],
            capture_output=True, text=True, timeout=30, env=env)
    except (OSError, subprocess.TimeoutExpired):
        raise ConfigError("git is not available")
    if proc.returncode != 0:
        raise ConfigError("not a git repository")
    drafts: list[dict] = []
    for chunk in proc.stdout.split("\x1e"):
        parts = chunk.strip("\n").split("\x1f", 2)
        if len(parts) != 3:
            continue
        commit_hash, subject, body = parts
        if not FAILURE_RE.search(subject + "\n" + body):
            continue
        drafts.append({
            "project": root.name,
            "title": subject[:240],
            "symptom": subject[:1000],
            "suspected_cause": body.strip()[:1000],
            "evidence_summary": f"git commit {commit_hash}: {subject}"[:1000],
        })
        if len(drafts) >= limit:
            break
    return drafts


def recall(repo: str, limit: int) -> int:
    """Print DRAFT incident JSON from failure-looking commits. Strictly dry-run."""
    root = Path(repo).expanduser()
    if not root.is_dir():
        raise ConfigError(f"not a directory: {repo}")
    drafts = git_log_failures(root.resolve(), max(1, limit))
    out = {
        "dry_run": True,
        "note": "drafts for human review; nothing was written to the kb",
        "repo": repo,
        "count": len(drafts),
        "drafts": drafts,
    }
    sys.stdout.write(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
    return 0


def _ask(label: str, default: str) -> str:
    raw = input(f"{label} [{default}]: ").strip()
    return raw or default


def _choose(target: str, location: str, yes: bool, default_target: str) -> tuple[str, str]:
    if yes or not sys.stdin.isatty():
        return target or default_target, location or "global"
    if not target:
        target = _ask("target (auto, all, cursor, claude, codex, kiro, commandcode)", default_target)
    if not location:
        location = _ask("location (global, local)", "global")
    if location not in {"global", "local"}:
        raise ConfigError(f"unknown location: {location}")
    return target, location


def install(target: str, location: str, yes: bool, refresh: bool, home: Path, root: Path,
            command: str) -> int:
    target, location = _choose(target, location, yes, "auto")
    agents = select_agents(target, home)
    if not agents:
        print("no agent configs found", file=sys.stderr)
        return 1
    for agent in agents:
        path = config_path(agent, location, home, root)
        status = apply_install(path, agent, command, refresh, location)
        print(f"{agent:8} {location:6} {status:10} {path}")
    print("Restart the client so it reloads MCP servers.")
    return 0


def uninstall(target: str, location: str, yes: bool, home: Path, root: Path) -> int:
    target, location = _choose(target, location, yes, "all")
    for agent in select_agents(target, home):
        path = config_path(agent, location, home, root)
        status = apply_uninstall(path, agent)
        print(f"{agent:8} {location:6} {status:10} {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dfiu")
    parser.add_argument("-V", "--version", action="store_true")
    sub = parser.add_subparsers(dest="cmd")

    p_serve = sub.add_parser("serve", help="MCP server over stdio")
    p_serve.add_argument("--project", default="", help="workspace directory")

    p_inst = sub.add_parser("install", help="register dfiu with Cursor, Claude Code, Codex, Kiro, and Command Code")
    p_inst.add_argument("-t", "--target", default="", help="auto, all, or cursor,claude,codex,kiro,commandcode")
    p_inst.add_argument("-l", "--location", default="", choices=["", "global", "local"])
    p_inst.add_argument("-y", "--yes", action="store_true", help="global + auto, no prompt")
    p_inst.add_argument("--refresh", action="store_true", help="update existing dfiu entries only")
    p_inst.add_argument("--print-config", metavar="ID", help="print one snippet and exit")

    p_un = sub.add_parser("uninstall", help="remove the dfiu entry from agent configs")
    p_un.add_argument("-t", "--target", default="")
    p_un.add_argument("-l", "--location", default="", choices=["", "global", "local"])
    p_un.add_argument("-y", "--yes", action="store_true", help="global + all, no prompt")

    p_recall = sub.add_parser(
        "recall",
        help="scan git log for failure-looking commits and print DRAFT incident JSON; writes nothing")
    p_recall.add_argument("--repo", required=True, help="git repository to scan")
    p_recall.add_argument("--limit", type=int, default=10, help="max drafts to print (default 10)")

    sub.add_parser("version", help="print the version")

    args = parser.parse_args(argv)
    try:
        if args.version or args.cmd == "version":
            print(version())
            return 0
        if args.cmd == "serve":
            return serve(args.project)
        if args.cmd == "install" and args.print_config:
            agent = args.print_config.strip().lower()
            if agent not in AGENTS:
                raise ConfigError(f"unknown target: {agent}")
            sys.stdout.write(snippet(agent, command_path()))
            return 0
        if args.cmd == "install":
            return install(args.target, args.location, args.yes, args.refresh,
                           Path.home(), Path.cwd(), command_path())
        if args.cmd == "uninstall":
            return uninstall(args.target, args.location, args.yes, Path.home(), Path.cwd())
        if args.cmd == "recall":
            return recall(args.repo, args.limit)
    except ConfigError as e:
        print(f"dfiu: {e}", file=sys.stderr)
        return 1
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
