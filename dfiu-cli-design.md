# DFIU: diseño del CLI y empaquetado (inspirado en codegraph)

> DFIU (Don't F*ck It Up) = Failure Mode & Pre-Flight Knowledge Base. Base funcional: `mcp_failure_preflight_spec_v2.md`. Este documento define solo CLI, empaquetado, descubrimiento de proyecto y arranque del servidor MCP. Referencia estudiada: `colbymchenry/codegraph` v1.6.2 (clon en `/workspace/codegraph-ref`).

## 1. Cómo lo hace codegraph

**Empaquetado.** Paquete npm `@colbymchenry/codegraph` con `bin: {"codegraph": "./dist/bin/codegraph.js"}`; además ofrece un instalador `curl … install.sh | sh` que trae un runtime empaquetado (no requiere Node). `codegraph upgrade` detecta cómo se instaló. Hook `preuninstall` limpia configs.

**CLI** (`src/bin/codegraph.ts`, commander + @clack/prompts):
| Comando | Qué hace |
|---|---|
| `codegraph` / `install` | Instalador interactivo: escribe la entrada MCP en cada agente (`--target auto|all|<ids>`, `--location global|local`, `--yes`, `--init`, `--print-config <id>`, `--refresh`). |
| `uninstall` | Quita configs de agentes y el CLI (`--keep-cli`). |
| `init [path]` | Crea `.codegraph/`, construye el índice e instala git hooks de sync. Se niega en `$HOME` o `/` salvo `--force`. |
| `uninit [path]` | Borra `.codegraph/` y retira los git hooks (con confirmación). |
| `index [path]` | Reindexado completo. Con ruta explícita no sube a directorios padres. |
| `sync [path]` | Actualización incremental (la llaman los git hooks). |
| `status [path]` | Estadísticas y salud del índice. |
| `query`, `explore`, `context`, `node`, `files`, `callers`, `callees`, `impact` | Las mismas consultas que exponen las herramientas MCP, en terminal (`--json`). |
| `affected [files…]` | Tests afectados por archivos cambiados (args o `--stdin`, p. ej. desde `git diff --name-only`). |
| `serve --mcp` (oculto) | Servidor MCP por stdio. Si stdin es TTY, explica que lo lanza el agente en vez de quedarse colgado. |
| `daemon` | Lista/detiene daemons compartidos. |
| `unlock` | Borra un lock obsoleto. |
| `prompt-hook` (oculto) | Hook `UserPromptSubmit` de Claude Code: lee `{prompt,cwd}` por stdin e inyecta contexto. |
| `ui`, `telemetry`, `upgrade`, `version` | Visor, telemetría opt-out, actualización, versión. |

**Datos.** Por proyecto en `.codegraph/` (override `CODEGRAPH_DIR`, solo un nombre de directorio, validado contra `..`/separadores). Base `codegraph.db` (SQLite), más `daemon.pid`, socket y `writer.pid` (un solo escritor por proyecto).

**Registro en clientes** (`src/installer/targets/*.ts`, uno por agente: claude, cursor, codex, gemini, opencode, kiro, copilot…). Todos escriben `{"command":"codegraph","args":["serve","--mcp"]}`:
- Claude Code: global `~/.claude.json` (o `$CLAUDE_CONFIG_DIR`), local `./.mcp.json`; permisos auto-allow en `~/.claude/settings.json` o `./.claude/settings.json`; opcionalmente el `prompt-hook`.
- Cursor: `~/.cursor/mcp.json` o `./.cursor/mcp.json`, agregando `--path` porque Cursor no siempre pasa la raíz.
- Edición idempotente con `jsonc-parser` (preserva comentarios) y TOML para Codex.

**Hooks.** Git `post-commit`, `post-merge`, `post-checkout` (respeta `core.hooksPath`) entre marcadores `# >>> codegraph sync hook >>>`, ejecutando `codegraph sync` en segundo plano; la desinstalación conserva el contenido del usuario. Además, el file watcher del servidor.

**Servidor MCP** (`src/mcp/`). JSON-RPC por líneas sobre stdio (transporte propio, no el SDK). Lo lanza el cliente con `codegraph serve --mcp`. Raíz del proyecto: `--path`, si no `rootUri`/roots del cliente o `cwd`; busca `.codegraph/` subiendo directorios y, si no, baja de forma acotada para adoptar un único subproyecto indexado; aplica `realpath`. Si hay raíz, el proceso stdio actúa como **proxy** hacia un daemon compartido por proyecto (socket bajo `.codegraph/`) para tener un solo watcher y escritor; `CODEGRAPH_NO_DAEMON=1` lo fuerza a correr en el mismo proceso. Herramientas: `codegraph_search`, `codegraph_callers`, `codegraph_callees`, `codegraph_impact`, `codegraph_node`, `codegraph_explore`, `codegraph_status`, `codegraph_files`. Los logs van solo a stderr (stdout es el protocolo).

**Qué copiamos y qué no.** Sí copiamos el directorio por proyecto, la búsqueda hacia arriba de la raíz, `serve --mcp` lanzado por el cliente con el aviso si stdin es TTY, el instalador por target con `--print-config`, la edición idempotente, los hooks con marcadores y paridad CLI↔MCP. No copiamos daemon, proxy, socket, watcher, telemetría, runtime empaquetado ni prompt-hook: DFIU es pequeño, sin red y SQLite en WAL alcanza con varios procesos.

## 2. Estructura del paquete

```
dfiu/
  pyproject.toml
  src/dfiu/
    __init__.py        # __version__
    __main__.py        # python -m dfiu
    cli.py             # argparse (stdlib) — subcomandos
    project.py         # descubrimiento de raíz y rutas
    core/              # lógica de la spec v2 §3–§9 (db, migrations, grammar, secrets, service, compile)
    mcp_server.py      # FastMCP: registra las 8 herramientas delegando en core/
    gitdiff.py         # git diff → ChangeSummaryV1
    installers/        # claude.py, cursor.py, codex.py, generic.py
    hooks.py           # git hooks con marcadores
  tests/
```

La lógica vive en `core/`; tanto el CLI como el servidor MCP la llaman, sin duplicarla (paridad igual que en codegraph).

`pyproject.toml`:
```toml
[project]
name = "dfiu"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = ["mcp>=1.2,<2"]          # fijar exacto en el lock
[project.scripts]
dfiu = "dfiu.cli:main"
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
```

Instalación: `uv tool install dfiu`, `pipx install dfiu` o, sin instalar, `uvx dfiu …`. Para desarrollo: `uv pip install -e .`. El CLI no usa más dependencias que `mcp` (argparse, sqlite3, tomllib y json son de la stdlib); no hay telemetría ni chequeo de actualizaciones en red.

## 3. Descubrimiento de proyecto y datos

- Directorio de datos: `<raíz>/.dfiu/` (override `DFIU_DIR`, que debe ser un nombre simple; se rechazan `/`, `..` y rutas absolutas).
  - `.dfiu/kb.sqlite3` (0600), `.dfiu/config.toml` (versionable), `.dfiu/artifacts/{invariants.json,active_rules.md}`, `.dfiu/.gitignore` generado con `kb.sqlite3*` y, en la política B, también `artifacts/`.
- `config.toml`: `project`, `git_policy = "B"|"A"`, `default_services` (mapa glob→servicio para el diff), límites (`max_matches`, entropía).
- Orden de resolución de la raíz:
  1. `--project <ruta>` o `DFIU_PROJECT`; con una ruta explícita no se busca hacia arriba (lección del issue #1524 de codegraph).
  2. Subir desde `cwd` hasta encontrar `.dfiu/config.toml`.
  3. En modo MCP, las roots del cliente (`list_roots`) si el cliente las ofrece.
  4. Si no hay raíz, los comandos fallan con `not_initialized` y sugieren `dfiu init`; el servidor MCP arranca igual y cada herramienta devuelve ese error estructurado, sin crear la base en un lugar inesperado.
- Se aplica `realpath` a la raíz. `init` se niega en `$HOME` o `/` salvo `--force`.
- El servidor MCP y el CLI pueden correr a la vez: WAL más `BEGIN IMMEDIATE` y `busy_timeout` (spec §2). No hace falta daemon.

## 4. Comandos `dfiu`

Convenciones: `--project`, `--json` (salida idéntica al contrato MCP de la spec §8) y `-q`. Códigos de salida: 0 ok/clear, 1 error, 2 `alert` con severidad `blocker`, 3 `insufficient_context`; un `alert` sin blocker sale con 0, o con 2 si se usa `--strict`. Los logs van a stderr.

| Comando | Descripción |
|---|---|
| `dfiu init [path] [--project-name N] [--git-policy A|B] [--hooks] [--force] [-y]` | Crea `.dfiu/`, `config.toml`, `.gitignore` interno y aplica migraciones; con `--hooks` instala el hook de pre-commit. |
| `dfiu uninit [path] [--force]` | Retira los hooks y borra `.dfiu/` previa confirmación (con backup `kb.sqlite3.bak` salvo `--no-backup`). |
| `dfiu migrate` | Aplica las migraciones pendientes (`user_version`) con backup previo. |
| `dfiu status` | Muestra raíz, versión de esquema, conteos por estado de incidentes y reglas, reglas `stale` con su motivo, hash del artefacto compilado vs actual (drift) y clientes MCP configurados. |
| `dfiu compile [--check]` | Ejecuta `compile_artifacts`. Con `--check` no escribe y sale con 1 si hay drift (CI de la política A). Alias: `dfiu index`. |
| `dfiu preflight [--staged | --base REF | --summary FILE|-] [--services s,…] [--change-type t,…] [--strict]` | Arma un `ChangeSummaryV1` desde `git diff --name-only` (§5) o lo lee de un JSON, y llama a `preflight_check`. |
| `dfiu summary [--staged | --base REF]` | Imprime el `ChangeSummaryV1` generado sin evaluarlo, para depurar o pasarlo a un agente. |
| `dfiu record …` | Equivale en CLI a `record_failure`; por flags o con `--from FILE.json`. |
| `dfiu verify …` | Equivale a `verify_resolution` (`--precondition nombre=pass` repetible). |
| `dfiu rule activate|deprecate|show|list <id>` | `activate_rule` y `deprecate_rule` (piden `--reviewer` y `--reason`), más detalle y lista con filtros por estado. |
| `dfiu incident show <id> [--sections …]` | Equivale a `get_incident_details`, con la misma redacción. |
| `dfiu serve` (alias `dfiu mcp`) | Servidor MCP por stdio (§6). Si stdin es TTY, explica que lo lanza el cliente y termina. |
| `dfiu install [--target claude,cursor,codex|auto|all] [--scope user|project] [--print-config ID] [--launcher dfiu|uvx] [-y]` | Registra el servidor en los clientes MCP (§7). |
| `dfiu uninstall [--target …] [--scope …]` | Elimina solo la entrada `dfiu` de cada config, sin tocar las demás. |
| `dfiu hooks install|uninstall [--pre-commit] [--pre-push]` | Hook git con marcadores que ejecuta `dfiu preflight --staged`; no bloquea salvo con `--strict`. |
| `dfiu doctor` | Diagnostica la versión de Python y de `mcp`, si SQLite tiene FTS5, permisos de `.dfiu/`, que la base no esté versionada en Git y la validez de las configs de los clientes. |
| `dfiu version` | Imprime la versión del paquete y del esquema. |

## 5. `dfiu preflight` desde git diff

1. Archivos: `git diff --name-only -z` según el modo: `--staged` → `--cached`; `--base REF` → `REF...HEAD`; por defecto, el working tree contra `HEAD` más los archivos sin trackear (`git ls-files --others --exclude-standard`). Rutas relativas a la raíz, normalizadas POSIX y deduplicadas. Los archivos borrados y los renombrados (origen y destino) cuentan como tocados.
2. `services`: los flags `--services` o el mapa `[services]` de `config.toml` (`"deploy/**" = "infra"`, `"src/api/**" = "api"`), evaluados con el mismo glob restringido de la spec §5. Si no hay mapa ni flag, la lista va vacía con `empty_reason="sin mapa de servicios"`, lo que da `insufficient_context` si alguna regla depende de `services`.
3. `change_type`: heurística determinista y documentada, sobreescribible con `--change-type`:
   - `docs`: `*.md`, `docs/**`
   - `test`: `tests/**`, `*_test.*`, `test_*`
   - `dependency`: lockfiles, `pyproject.toml`, `package.json`, `requirements*.txt`
   - `schema`: `migrations/**`, `*.sql`
   - `infra`: `Dockerfile*`, `compose*.y*ml`, `*.tf`, `k8s/**`, `.github/workflows/**`
   - `config`: `*.toml`, `*.ini`, `*.env.example`, `*.y*ml` restantes
   - `firmware`: `*.ino`, `*.ld`, `*.hex`, `firmware/**`
   - `code`: el resto
4. `revision`: `git rev-parse HEAD`, o `"unknown"` si no hay commits. `operation` y `environment_tags` solo se pasan por flag.
5. Nunca se lee el contenido del diff: solo nombres de archivo, coherente con la política de no ingerir logs ni código.
6. Sin repo git, el comando falla y pide `--summary`.

## 6. Servidor MCP: cómo se lanza

- Comando registrado en el cliente: `dfiu serve`, o bien `uvx dfiu serve` (`--launcher uvx`) para no depender del PATH.
- `serve` resuelve la raíz con §3 (más `--project` si la config lo fija) **antes** de `mcp.run(transport="stdio")`. Si no la encuentra, registra un handler para leer las roots del cliente al primer uso.
- El servidor expone las 8 herramientas de la spec §8 con nombres prefijados para evitar choques entre servidores: `dfiu_record_failure`, `dfiu_verify_resolution`, `dfiu_activate_rule`, `dfiu_deprecate_rule`, `dfiu_compile_artifacts`, `dfiu_list_active_invariants`, `dfiu_preflight_check` y `dfiu_get_incident_details`. Más `dfiu_status` (solo lectura, al estilo de `codegraph_status`).
- Las `instructions` de FastMCP llevan un texto breve: "antes de un cambio riesgoso, llama a `dfiu_preflight_check` con un `ChangeSummaryV1`; pide detalles solo si hay alerta".
- stdout se reserva para JSON-RPC; el logging va a stderr con `DFIU_LOG_LEVEL`. Al cerrarse stdin (EOF) el proceso termina; no hay daemon, socket ni watcher. La obsolescencia de reglas se recalcula de forma perezosa en cada llamada (spec §3.3).
- Un proceso por sesión de cliente. La concurrencia la resuelve SQLite.

## 7. Registro en clientes (`dfiu install`)

Entrada que se escribe (idempotente, bajo la clave `dfiu`):
```json
{"mcpServers": {"dfiu": {"command": "dfiu", "args": ["serve", "--project", "<raíz absoluta>"]}}}
```
Con `--scope user` se omite `--project` y se confía en `cwd`/roots. Con `--launcher uvx`: `"command": "uvx", "args": ["dfiu", "serve"]`.

| Target | `--scope project` | `--scope user` | Formato |
|---|---|---|---|
| `claude` | `./.mcp.json` | `~/.claude.json` (o `$CLAUDE_CONFIG_DIR/.claude.json`) | JSON `mcpServers` |
| `cursor` | `./.cursor/mcp.json` (siempre con `--project`, porque Cursor no garantiza el cwd) | `~/.cursor/mcp.json` | JSON `mcpServers` |
| `codex` | — | `~/.codex/config.toml` `[mcp_servers.dfiu]` | TOML |
| `generic` | `--print-config` imprime el fragmento | — | JSON |

Reglas:
- Leer, parsear y modificar solo `mcpServers.dfiu`, sin tocar otras entradas.
- Antes de escribir, hacer backup `*.dfiu.bak` y escribir de forma atómica.
- Si el JSON es inválido, abortar sin escribir.
- Para preservar comentarios en archivos JSONC, avisar y ofrecer `--print-config` en vez de reescribir.
- `--refresh` solo actualiza las entradas `dfiu` que ya existen.
- No se escriben permisos de auto-allow por defecto; se ofrecen con un flag explícito `--allow-readonly`, que permite solo `dfiu_preflight_check`, `dfiu_list_active_invariants`, `dfiu_get_incident_details` y `dfiu_status`. Las herramientas de escritura y activación siempre piden confirmación al usuario en el cliente.
- Tras instalar, se imprime "reinicia el cliente".

## 8. Git hooks

`dfiu hooks install` escribe en `$(git rev-parse --git-path hooks)/pre-commit` (respeta `core.hooksPath`) un bloque entre marcadores:
```sh
# >>> dfiu preflight hook >>>
command -v dfiu >/dev/null 2>&1 && dfiu preflight --staged -q || true
# <<< dfiu preflight hook <<<
```
Con `--strict`, se quita `|| true` y el commit se bloquea solo si hay una regla `blocker` (código de salida 2). `uninstall` elimina solo el bloque entre marcadores; si el archivo queda solo con el shebang, lo borra. Opcional: `pre-push` con `--base @{upstream}`. CI: `dfiu compile --check` y `dfiu preflight --base origin/main --strict`.

## 9. Tests del CLI (complementan la spec §12)

- Descubrimiento: subdirectorio → raíz; ruta explícita sin `.dfiu/` → error (no sube); `DFIU_DIR` inválido → ignorado con aviso.
- `summary` sobre repos fixture: modificados, staged, renombrados, borrados y sin trackear; heurística de `change_type`; mapa de servicios.
- Códigos de salida de `preflight` (0/1/2/3) y `--strict`.
- `install`: configs con otras entradas preservadas, idempotencia, JSON inválido → no escribe, `--print-config` sin escrituras, `uninstall` limpio.
- Hooks: instalación idempotente, preservación del hook del usuario, `core.hooksPath`.
- `serve` con TTY → mensaje y salida 0; prueba de handshake stdio real con el SDK `mcp` (initialize + `tools/list` muestra las 9 herramientas).
- `compile --check` detecta drift.

## 10. Orden de implementación
1. `core/` según la spec v2, reutilizando el código de referencia §11.
2. `project.py` + `init` / `status` / `migrate`.
3. `mcp_server.py` + `serve` y la prueba de handshake.
4. `gitdiff.py` + `summary` / `preflight` + hooks.
5. `compile`, `rule`, `record`, `verify`, `incident`.
6. `install` / `uninstall` (claude, cursor, codex) y `doctor`.
7. Publicación: `uv build` y publicación privada o en PyPI; documentar `uvx dfiu`.
