# DFIU (Don't F*ck It Up)

Servidor MCP local (stdio) de incidentes e invariantes de pre-flight. Sin red y sin LLM.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python server.py
```

`FAILURE_KB_DIR` (default `.failure-kb`) y `FAILURE_KB_ARTIFACTS` (default `.failure-kb/artifacts`).

Política Git B: `.failure-kb/` no se versiona. La base SQLite tampoco. Los artefactos se regeneran con `compile_artifacts`.

```bash
.venv/bin/python -m unittest test_mvp
```

`mcp` queda fijado en 1.30.0 (`requirements.lock`). mcp 2.x renombró FastMCP.
