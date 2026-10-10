import json
import tempfile
import unittest
from pathlib import Path

import cli


SAMPLE_JSON = """{
  "mcpServers": {
    "other": {
      "command": "other",
      "args": ["--flag"],
      "env": {"TOKEN": "keep-me"}
    }
  }
}
"""

SAMPLE_TOML = """\
model = "x"

[mcp_servers.other]
command = "other"
args = ["--flag"]

[mcp_servers.other.env]
TOKEN = "keep-me"
"""


class MergeTest(unittest.TestCase):
    def test_json_keeps_other_servers_and_is_stable(self) -> None:
        entry = cli.json_entry("/usr/local/bin/dfiu", cli.entry_args("cursor"))
        once = cli.upsert_mcp_json(SAMPLE_JSON, entry)
        twice = cli.upsert_mcp_json(once, entry)
        self.assertEqual(once, twice)
        data = json.loads(once)
        self.assertEqual(data["mcpServers"]["other"]["env"]["TOKEN"], "keep-me")
        self.assertEqual(data["mcpServers"]["dfiu"]["args"], ["serve", "--project", "${workspaceFolder}"])

    def test_json_remove_only_dfiu(self) -> None:
        entry = cli.json_entry("dfiu", ["serve"])
        merged = cli.upsert_mcp_json(SAMPLE_JSON, entry)
        removed = cli.remove_mcp_json(merged)
        self.assertNotIn("dfiu", json.loads(removed)["mcpServers"])
        self.assertIn("other", json.loads(removed)["mcpServers"])

    def test_invalid_json_does_not_parse(self) -> None:
        with self.assertRaises(cli.ConfigError):
            cli.upsert_mcp_json("{nope", cli.json_entry("dfiu", ["serve"]))

    def test_toml_keeps_other_tables(self) -> None:
        once = cli.upsert_codex_toml(SAMPLE_TOML, "/bin/dfiu", ["serve"])
        twice = cli.upsert_codex_toml(once, "/bin/dfiu", ["serve"])
        self.assertEqual(once, twice)
        self.assertIn('[mcp_servers.other]', once)
        self.assertIn('TOKEN = "keep-me"', once)
        self.assertIn('command = "/bin/dfiu"', once)
        gone = cli.remove_codex_toml(once)
        self.assertNotIn("mcp_servers.dfiu", gone)
        self.assertIn("mcp_servers.other.env", gone)

    def test_cursor_project_arg_claude_plain(self) -> None:
        self.assertEqual(cli.entry_args("cursor")[-1], "${workspaceFolder}")
        self.assertEqual(cli.entry_args("claude"), ["serve"])
        self.assertEqual(cli.entry_args("codex"), ["serve"])
        self.assertEqual(cli.entry_args("kiro"), ["serve"])
        self.assertEqual(cli.entry_args("commandcode"), ["serve"])

    def test_kiro_and_commandcode(self) -> None:
        home, root = Path("/home/u"), Path("/work")
        self.assertEqual(cli.config_path("kiro", "global", home, root), home / ".kiro/settings/mcp.json")
        self.assertEqual(cli.config_path("kiro", "local", home, root), root / ".kiro/settings/mcp.json")
        self.assertEqual(cli.config_path("commandcode", "global", home, root), home / ".commandcode/mcp.json")
        self.assertEqual(cli.config_path("commandcode", "local", home, root), root / ".mcp.json")
        kiro = cli.agent_entry("kiro", "dfiu", "global")
        self.assertEqual(kiro["args"], ["serve"])
        self.assertFalse(kiro["disabled"])
        self.assertNotIn("type", kiro)
        shared = cli.agent_entry("commandcode", "dfiu", "local")
        self.assertEqual(shared, cli.agent_entry("claude", "dfiu", "local"))
        self.assertEqual(shared["transport"], "stdio")
        self.assertEqual(cli.agent_entry("commandcode", "dfiu", "global")["transport"], "stdio")

    def test_refresh_skips_missing_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mcp.json"
            path.write_text(SAMPLE_JSON, encoding="utf-8")
            self.assertEqual(cli.apply_install(path, "cursor", "dfiu", refresh=True), "skipped")
            self.assertNotIn("dfiu", path.read_text(encoding="utf-8"))
            self.assertEqual(cli.apply_install(path, "cursor", "dfiu", refresh=False), "updated")
            self.assertEqual(cli.apply_install(path, "cursor", "dfiu", refresh=True), "unchanged")

    def test_install_roundtrip_on_fake_home(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / ".cursor").mkdir()
            (home / ".cursor" / "mcp.json").write_text(SAMPLE_JSON, encoding="utf-8")
            (home / ".claude.json").write_text("{}\n", encoding="utf-8")
            codex = home / ".codex"
            codex.mkdir()
            (codex / "config.toml").write_text(SAMPLE_TOML, encoding="utf-8")
            self.assertEqual(cli.detected(home), ["cursor", "claude", "codex"])
            rc = cli.install("auto", "global", True, False, home, home, "/opt/dfiu")
            self.assertEqual(rc, 0)
            cursor = json.loads((home / ".cursor" / "mcp.json").read_text(encoding="utf-8"))
            self.assertEqual(cursor["mcpServers"]["other"]["env"]["TOKEN"], "keep-me")
            self.assertEqual(cursor["mcpServers"]["dfiu"]["command"], "/opt/dfiu")
            claude = json.loads((home / ".claude.json").read_text(encoding="utf-8"))
            self.assertEqual(claude["mcpServers"]["dfiu"]["args"], ["serve"])
            toml = (codex / "config.toml").read_text(encoding="utf-8")
            self.assertIn('TOKEN = "keep-me"', toml)
            self.assertEqual(cli.uninstall("all", "global", True, home, home), 0)
            cursor = json.loads((home / ".cursor" / "mcp.json").read_text(encoding="utf-8"))
            self.assertNotIn("dfiu", cursor["mcpServers"])
            self.assertNotIn("mcp_servers.dfiu", (codex / "config.toml").read_text(encoding="utf-8"))

    def test_serve_rejects_missing_project(self) -> None:
        with self.assertRaises(cli.ConfigError):
            cli.serve_project("/no/such/dfiu-project", is_tty=False)
        self.assertIsNone(cli.serve_project("", is_tty=True))


if __name__ == "__main__":
    unittest.main()
