# Especificación técnica v2: DFIU (Don't F*ck It Up) — Failure Mode & Pre-Flight Knowledge Base (MCP local)

> Versión consolidada 2. Sustituye a `mcp_failure_preflight_spec.md` (que se conserva sin cambios). El alcance MVP son §1–§12; el **Anexo: Fase 2** es orientativo y no bloquea el MVP. Ante contradicción, prevalece el cuerpo principal y, dentro de él, el código de §11 como referencia del contrato.
>
> Enmienda DFIU. `server.py` prevalece sobre el bloque de §11 en cinco puntos: (1) cero reglas evaluables → `no_coverage`, nunca `clear`; (2) `files_touched` y `change_type` se unen con el diff git del directorio de trabajo, sin adoptar un repo padre; (3) `hypothesis` y `verified` salen en `hypothesis_matches` con severidad `info` y no bloquean; (4) mismo directorio o la misma familia de `error_code` salen en `variant_matches`; (5) cada preflight se anota en `preflight_log`, `record_failure` lo marca `recurred` y `preflight_stats` devuelve los conteos. Nada de eso sale de la máquina.

## 1. Resumen ejecutivo

Servidor MCP local, embebido en el repositorio de un proyecto, para capturar fallos, verificar resoluciones con evidencia y convertir conocimiento validado en invariantes que se evalúan antes de cambios potencialmente peligrosos.

Implementación pequeña y determinista: Python 3.11+, `sqlite3` de la biblioteca estándar y el paquete `mcp` (FastMCP) con versión fijada en el lock del proyecto. Transporte stdio. Sin red, sin LLM, sin vector store, sin telemetría. Ninguna herramienta ejecuta cambios técnicos (flasheos, Docker, SQL externo).

Unidad de conocimiento: el **incidente** (síntoma, causa sospechada, resolución, evidencia). Una **regla** nace en `hypothesis`, pasa a `verified` solo con una verificación efectiva y a `active` solo por activación explícita de un revisor. `preflight_check` recibe un `ChangeSummaryV1` (§4), evalúa condiciones con una gramática cerrada (§5) y devuelve coincidencias compactas, nunca historiales ni logs.

### Objetivos
- Prevenir recurrencias conocidas con baja latencia y bajo consumo de tokens.
- Separar detección barata (pre-flight) de recuperación detallada (bajo demanda, por id).
- Trazabilidad incidente → verificación → regla → artefacto.
- Ciclo de vida explícito: activación, obsolescencia (`stale`), deprecación y reactivación auditadas.

### Fuera de alcance (MVP)
- Diagnóstico automático, reparación autónoma o ejecución de cambios.
- Ingesta de conversaciones, volcados o logs extensos.
- Búsqueda semántica/embeddings, árboles diagnósticos, deduplicación, perfiles de dominio (ver Anexo).

## 2. Arquitectura y límites

1. Cliente MCP (agente/editor) → proceso local por stdio. No se abre ningún socket.
2. Capa de herramientas (§8): validación de tipos, límites y formato de error estándar.
3. Capa de servicio: normalización, **detección/redacción de secretos (§7)**, transacciones.
4. SQLite local (`.failure-kb/kb.sqlite3`, configurable por `FAILURE_KB_DIR`), permisos solo del usuario (0600), **excluido de Git**.
5. Compilador determinista (§9) → `invariants.json` (canónico) y `active_rules.md` (vista derivada) en una ruta fija configurada (`FAILURE_KB_ARTIFACTS`), nunca una ruta recibida del modelo.

Conexión: `PRAGMA foreign_keys=ON`, `journal_mode=WAL`, `busy_timeout=5000`. Cada operación usa **una conexión, una transacción `BEGIN IMMEDIATE` y un único timestamp** (UTC ISO-8601 con microsegundos), y cierra la conexión al terminar. Escritura de artefactos: archivo temporal + `fsync` + `os.replace` atómico.

### Privacidad
- No existen campos `conversation`, `history` ni `raw_logs`.
- Todo texto libre pasa por §7 antes de persistir y antes de responder.
- `preflight_check` no persiste el resumen recibido.
- Límites duros por campo (§6); exceder un límite devuelve `too_large`, no trunca en silencio.

## 3. Estados y transiciones

### 3.1 Estados de incidente
| Estado | Significado |
|---|---|
| `open` | Registrado; sin resolución verificada. |
| `change_applied_unverified` | Se aplicó un cambio, aún sin verificación efectiva (lo fija el cliente vía Fase 2; en MVP es opcional). |
| `verified_resolved` | Existe al menos una verificación **efectiva** (§8.2). Único estado que permite afirmar "resuelto". |
| `reopened` | Un `fail` posterior a `verified_resolved`. La evidencia anterior se conserva. |
| `closed` | Cierre administrativo (fuera del MVP automático). |

Transiciones automáticas en MVP: `open|reopened|change_applied_unverified → verified_resolved` (pass efectivo); `verified_resolved → reopened` (fail). Nunca se borra `verification_log`.

### 3.2 Estados de regla
| Estado | Participa en pre-flight | Se compila |
|---|---|---|
| `hypothesis` | Sí, `hypothesis_matches` (severidad `info`, no bloquea, no compila) | No |
| `verified` | Igual que `hypothesis` hasta que alguien la active | No |
| `active` | Sí (`matches`) | Sí |
| `stale` | Solo como `stale_matches` ("requiere revalidación"); nunca produce `clear` ni bloqueo | No |
| `deprecated` | No | No |

### 3.3 Tabla de transiciones de regla
| Desde → Hacia | Disparador | Requisitos |
|---|---|---|
| hypothesis → verified | `verify_resolution` con pass efectivo y `rule_id` vinculado | Gate §8.2 |
| verified → active | `activate_rule` | `reviewer`, `reason`, `last_verified_at` no nulo |
| active → stale | Automático en `preflight_check`, `list_active_invariants`, `compile_artifacts` | `valid_until`/`review_after` vencido o `dependency_fingerprint` distinto |
| stale → active | `activate_rule` | Verificación efectiva **posterior** a la transición a stale; incrementa `revision` y recalcula hash/fingerprint |
| hypothesis/verified/active/stale → deprecated | `deprecate_rule` | `reason` y `reviewer` obligatorios |
| deprecated → hypothesis | Reapertura explícita (herramienta de Fase 2 o migración manual auditada) | Nueva revisión; nunca reactivación directa |

Cualquier otra transición devuelve `illegal_transition`. Toda transición se registra en `rule_transitions` (append-only). Un `fail` sobre una regla reduce `confidence` en 0,2 (mín. 0) pero no cambia su estado: refutar exige `deprecate_rule`. Obsolescencia temporal ≠ refutación causal.

### 3.4 `dependency_fingerprint`
Al activar, el revisor declara `dependency_paths` (archivos relativos al repo de los que depende la invariante). Cálculo:

```
fingerprint = sha256( concat( for p in sorted(unique(normalize(p))):  p + "\0" + (sha256(bytes(p)) | "MISSING") + "\n" ) )
```

Rutas POSIX relativas, sin `..` ni absolutas; directorios no admitidos. Si el fingerprint actual difiere del guardado, la regla pasa a `stale` con `stale_reason="dependencias cambiaron"`. Sin `dependency_paths` solo aplican `valid_until`/`review_after`.

## 4. Contrato de entrada del pre-flight: `ChangeSummaryV1`

Única entrada de `preflight_check` (reemplaza `subsystem/error_code/changed_paths/condition_hash` de la v1).

| Campo | Tipo | Oblig. | Reglas |
|---|---|---|---|
| `schema_version` | int | Sí | Debe ser `1`; otro valor → error `unsupported_schema`. |
| `project` | string ≤160 | Sí | Filtra reglas por proyecto. |
| `services` | string[] ≤200 | Sí* | Ordenado y deduplicado. |
| `files_touched` | string[] ≤200 | Sí* | Rutas POSIX relativas, sin `./`, `..` ni absolutas (→ `invalid_input`). |
| `change_type` | enum[] | Sí* | `code, config, dependency, schema, infra, firmware, docs, test`. |
| `environment_tags` | string[] ≤200 | No | Ordenado y deduplicado. |
| `operation`, `subsystem`, `error_code`, `revision` | string ≤200 | No | `revision` = git sha o `"unknown"` explícito. |
| `empty_reason` | string ≤200 | Cond. | Requerido si algún campo `*` es `[]`. |

(*) Si falta un campo obligatorio, o está vacío sin `empty_reason`, aparece en `missing_fields` y el estado global nunca es `clear` (será `insufficient_context` salvo que haya alertas).

```json
{"schema_version":1,"project":"pterodactyl","services":["node"],
 "files_touched":["deploy/compose.yaml"],"change_type":["config"],
 "operation":"deploy","environment_tags":["docker"],"revision":"abc123"}
```

Cambios incompatibles del contrato incrementan `schema_version`; el servidor soporta explícitamente las versiones listadas.

## 5. Gramática de `condition_json`

Árbol JSON cerrado. Se valida al crear la regla (`invalid_condition` si no cumple) y nunca se ejecuta como código.

```
Node     := BoolNode | LeafNode
BoolNode := {"op": "all"|"any", "args": [Node, ...≥1]}
          | {"op": "not", "args": [Node]}
LeafNode := {"op": "exists", "field": Field}
          | {"op": "eq"|"prefix", "field": Scalar, "value": string}
          | {"op": "in", "field": Scalar, "value": [string, ...]}
          | {"op": "any_in", "field": List, "value": [string, 1..50]}
          | {"op": "touches_any"|"touches_all", "field": "files_touched", "value": [glob, 1..50]}
Scalar   := "project"|"operation"|"subsystem"|"error_code"|"revision"
List     := "services"|"files_touched"|"change_type"|"environment_tags"
```

- Límites: profundidad máxima **4**, máximo **32** nodos. Claves extra → inválido.
- Glob restringido (`fnmatchcase`): `*`, `?`; se prohíben clases `[]`. Sin regex.
- Semántica: `touches_any` = algún archivo coincide con algún glob; `touches_all` = cada glob coincide con al menos un archivo ("toca X y Y"). `any_in` = intersección no vacía. `exists` = campo presente y no vacío.
- Campo ausente en una hoja (salvo `exists`) → la regla queda en `insufficient_context` y el campo se agrega a `missing_fields`. `all` corta en el primer falso; `any` devuelve verdadero si alguna rama coincide aunque otra falte.
- El resultado incluye `matched`: lista de `op(field)` que coincidieron.

## 6. Modelo SQLite (esquema v1)

Migraciones versionadas con `PRAGMA user_version`; `migrate()` aplica en una transacción las pendientes en orden (`MIGRATIONS[i]` lleva a la versión `i+1`). Copia de seguridad antes de migraciones destructivas. El DDL normativo es el de §11 (`MIGRATIONS[0]`); resumen:

- **`incidents`**: `id`, `created_at`, `updated_at`, `project`, `subsystem`, `environment`, `title`(≤240), `symptom`(≤2000), `error_code`, `condition_hash`, `root_cause`(≤1000), `resolution`(≤1000), `status` CHECK §3.1, `evidence_summary`(≤1000), `evidence_ref`, `tags_json`, `sensitivity` CHECK(`normal`,`redacted`,`restricted`).
- **`rules`**: `id` (`R-` + 12 hex), `project`, `scope`, `title`, `invariant` (una línea, ≤200 caracteres; CHECK sin salto de línea), `condition_json`, `action`(≤200), `status` CHECK §3.2 (incluye `stale`), `severity` CHECK(`info`,`warning`,`blocker`), `confidence` [0,1], `revision`, `verification_count`, `last_verified_at`, `review_after`, `valid_until`, `stale_reason`, `deprecated_at`, `deprecation_reason`, `source_revision`, `dependency_paths_json`, `dependency_fingerprint`, `content_hash`; `UNIQUE(project, content_hash)`.
- **`incident_rules`** (N:M): reemplaza la FK circular `incidents.rule_id`.
- **`verification_log`** (append-only): `verdict`, `method` CHECK(`test`,`reproduction`,`regression`,`operator_review`), `success_criterion`, `preconditions_json`, `exercised_failing_path`, `environment`, `source_revision`, `condition_hash`, `evidence_summary`, `reviewer`.
- **`rule_transitions`** (append-only): `from_status`, `to_status`, `reason`, `actor`, `revision`, `created_at`.
- **`idempotency_keys`**: PK `(tool, key)`, `request_hash` (sha256 del request canónico), `response_json`. Misma clave + mismo request → misma respuesta; misma clave + request distinto → `idempotency_conflict`. Retención configurable (por defecto 30 días, purga en `migrate()` en Fase 2).
- **`artifact_state`**: último hash compilado por artefacto.

`content_hash = sha256(canonical_json({project, scope, condition, invariant, action, severity}))`.

## 7. Detección y redacción de secretos

**Capa**: servicio, en tres puntos: (a) antes de persistir cualquier texto libre (`scrub`), (b) al responder en `get_incident_details` (`redact` de nuevo, defensa en profundidad), (c) nunca se registra el valor detectado en logs ni warnings.

**Catálogo de alta confianza (regex, redacción automática a `[REDACTED:secret:<tipo>]`)**:
| Tipo | Patrón (resumen) |
|---|---|
| `private_key` | `-----BEGIN … PRIVATE KEY-----` hasta `END` |
| `aws_access_key` | `(AKIA|ASIA)[0-9A-Z]{16}` |
| `github_token` | `gh[pousr]_…{36,}`, `github_pat_…` |
| `slack_token` | `xox[abprs]-…` |
| `openai_like_key` | `sk-[A-Za-z0-9_-]{20,}` |
| `google_api_key` | `AIza…{35}` |
| `jwt` | `eyJ….….…` |
| `auth_header` | `Authorization:`/`Proxy-Authorization:` + valor (conserva el nombre) |
| `url_credentials` | `esquema://usuario:clave@` |
| `assignment` | `*PASSWORD*|*SECRET*|*TOKEN*|*API_KEY*|*PRIVATE_KEY* = valor` (conserva el nombre de variable) |

**Baja confianza (entropía)**: cadenas `[A-Za-z0-9+/=_-]{20,}` con entropía de Shannon **≥ 4,0 bits/carácter** (configurable). No se redactan automáticamente: se devuelve `warnings: ["<campo>: cadena de alta entropía, revisar"]` sin reproducir el valor, y el cliente puede reenviar el texto redactado.

**Reglas**: redacción idempotente (el marcador no vuelve a coincidir); si hubo redacción el incidente queda `sensitivity='redacted'`; con `restricted`, `get_incident_details` solo devuelve `title`, `status` y `error_code`. Allowlist y pragmas inline (`secret-scan: ignore-next-line reason=…`) quedan para Fase 2 y nunca podrán desactivar los tipos de alta confianza.

## 8. Herramientas MCP

Reglas comunes:
1. Entradas tipadas (anotaciones Python → esquema JSON de FastMCP).
2. Éxito: objeto con `"ok": true` y los campos documentados.
3. **Error estándar**: `{"ok": false, "error": {"code": <código>, "message": <texto breve>, "fields": [<campos>]}}`. Códigos: `invalid_input`, `too_large`, `not_found`, `unsupported_schema`, `invalid_condition`, `illegal_transition`, `verification_required`, `idempotency_conflict`, `conflict`, `internal`. Nunca trazas, rutas ni SQL.
4. Escrituras transaccionales; `record_failure` y `verify_resolution` aceptan `idempotency_key`.
5. Las listas en la salida tienen orden determinista documentado.

### 8.1 `record_failure`
Entrada: `project`*, `title`*, `symptom`*, `subsystem`, `environment`, `error_code`, `condition_hash`, `tags[]`, `suspected_cause`, `proposed_resolution`, `evidence_summary`, `proposed_invariant`, `proposed_action`, `condition` (§5), `scope`, `severity`, `idempotency_key`.
Comportamiento: crea incidente `open`. Si llega `proposed_invariant` o `condition`, exige los cuatro (`proposed_invariant`, `proposed_action`, `condition`, `scope`), valida la condición y crea una regla `hypothesis` vinculada en `incident_rules`.
Salida: `{ok, incident_id, status:"open", rule_id|null, rule_status:"hypothesis"|null, warnings[], next_step:"verify_resolution"}`.

### 8.2 `verify_resolution` (gate)
Entrada: `incident_id`*, `verdict`* (`pass|fail|inconclusive`), `method`*, `success_criterion`* (definido antes de la prueba), `preconditions`* (`{nombre: pass|fail|inconclusive|not_run}`, no vacío), `exercised_failing_path`* (bool: la prueba ejercita el camino que fallaba), `evidence_summary`*, `rule_id`, `environment`, `source_revision`, `condition_hash`, `reviewer`, `idempotency_key`.
**Pass efectivo** ⇔ `verdict=pass` ∧ todas las precondiciones `pass` ∧ `exercised_failing_path` ∧ `success_criterion` no vacío ∧ `method ≠ operator_review`. Si no, se registra igual pero no cambia estados y `pending_requirements` lista lo que falta.
`rule_id`, si se envía, debe existir y estar vinculado al incidente. Efectos: ver §3. Nunca activa una regla.
Salida: `{ok, incident_id, verdict, effective_pass, incident_status, rule_status|null, pending_requirements[], warnings[]}`.

### 8.3 `activate_rule`
Entrada: `rule_id`*, `reviewer`*, `reason`*, `dependency_paths[]`, `source_revision`, `review_after`, `valid_until` (ISO-8601 UTC), `severity`.
Requisitos: §3.3. Recalcula `content_hash` y `dependency_fingerprint`; desde `stale` incrementa `revision`.
Salida: `{ok, rule_id, status:"active", revision, content_hash, dependency_fingerprint|null}`.

### 8.4 `deprecate_rule`
Entrada: `rule_id`*, `reason`*, `reviewer`*, `evidence_ref`. Desde cualquier estado excepto `deprecated`.
Salida: `{ok, rule_id, status:"deprecated", deprecated_at}`.

### 8.5 `compile_artifacts`
Entrada: `project`*, `write` (bool, por defecto `true`). Primero refresca obsolescencia, luego compila (§9) y escribe en `FAILURE_KB_ARTIFACTS`.
Salida: `{ok, project, rule_count, artifact_sha256, written, files[]}`.

### 8.6 `list_active_invariants`
Entrada: `project`*, `scope`, `severity`, `limit` (1–200, por defecto 50). Solo lectura sobre el artefacto canónico en memoria.
Salida: `{ok, rules:[{id, scope, severity, invariant, action}], count, truncated, total_active, artifact_sha256}`; orden `scope, id`. `artifact_sha256` es el hash del `invariants.json` completo del proyecto (no de la vista filtrada).

### 8.7 `preflight_check`
Entrada: `summary`* (`ChangeSummaryV1`), `limit` (1–5).
Comportamiento: une `files_touched` y `change_type` con el diff git del cwd cuando el cwd es la raíz del repo; refresca obsolescencia; evalúa `active`, `stale`, `hypothesis` y `verified` con §5.
Salida: `{ok, status, matches:[{rule_id, severity, invariant, action, matched[], incident_ids[≤3]}], hypothesis_matches:[{rule_id, invariant, note, severity:"info"}], stale_matches:[{rule_id, invariant, note}], variant_matches:[{rule_id, invariant, note}], evaluated, missing_fields[], artifact_sha256, git_files[], next_tool}`.
`status`: `alert` si hay alguna de esas listas; si no, `insufficient_context` si `missing_fields` no está vacío; si no, `no_coverage` si no había reglas evaluables; si no, `clear`. Orden de `matches`: severidad (`blocker, warning, info`), luego `rule_id`. Solo `active` entra en `matches`.

### 8.9 `preflight_stats`
Entrada: `project`*.
Salida: `{ok, project, runs, by_status:{status: n}, recurred_after:{status: n}}`. `recurred_after` cuenta preflights de ese estado seguidos de un `record_failure` del mismo proyecto.

### 8.8 `get_incident_details`
Entrada: `incident_id`*, `sections` ⊆ {`summary`, `cause`, `resolution`, `references`, `verification`}, `max_chars` (200–8000, por defecto 2000).
Salida: `{ok, incident_id, sensitivity, <campos de las secciones>, verifications[≤5]}`; todo texto pasa por `redact`. Id inexistente → `not_found` sin enumerar otros.

## 9. Artefactos canónicos y política Git

`invariants.json` (canónico):
```json
{
  "project": "p",
  "rules": [
    {
      "action": "...",
      "content_hash": "...",
      "id": "R-...",
      "incident_ids": ["..."],
      "invariant": "...",
      "revision": 1,
      "scope": "network",
      "severity": "warning",
      "when": {"op": "...", "...": "..."}
    }
  ],
  "schema_version": 1
}
```
- Sin `generated_at` ni ningún campo volátil.
- Claves ordenadas recursivamente (`sort_keys`), indentación fija de 2 espacios, UTF-8 sin escapar, LF, newline final.
- `rules` ordenadas por `scope`, `id`; `incident_ids` ordenados (máx. 5).
- `artifact_sha256 = sha256(bytes exactos de invariants.json)`.
- `active_rules.md`: vista derivada, una línea por regla `- [severidad] \`id\` (scope): invariante -> acción`, mismo orden, LF.

**Política Git** (elegir una por repo y documentarla en el README):
- **(B, por defecto)**: `.failure-kb/` completo en `.gitignore`; artefactos generados localmente o en CI.
- **(A)**: versionar solo `invariants.json`/`active_rules.md`, con una prueba de CI que regenera y falla ante drift. Ante conflicto de merge, **regenerar** desde la base, nunca resolver a mano.

La base SQLite nunca se versiona.

## 10. Criterios de aceptación MVP
- Arranca por stdio, ejecuta migraciones hasta `user_version` actual, sin red.
- Las herramientas cumplen sus esquemas de salida y el formato de error estándar.
- Solo `active` produce `matches`; `stale` produce `stale_matches`; `hypothesis`/`verified` producen `hypothesis_matches`; ningún estado no activo se compila. Cero reglas → `no_coverage`.
- Ninguna regla llega a `active` sin pass efectivo y `activate_rule`.
- Compilación byte-idéntica entre ejecuciones; hash = sha256 del archivo.
- Ningún secreto del catálogo aparece en DB, artefactos ni respuestas.
- Toda transición de regla queda en `rule_transitions`.

## 11. Implementación de referencia (Python, FastMCP + SQLite)

Referencia compacta, verificada con `python -m py_compile` y con un smoke test local (stub de `mcp`). Antes de producción: fijar versión de `mcp`, comprobar la API FastMCP de esa versión y añadir la suite de §12.

```python
# server.py — DFIU v2 (MVP). Local, stdio, sin red ni LLM.
from __future__ import annotations

import fnmatch
import hashlib
import json
import math
import os
import re
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterator

from mcp.server.fastmcp import FastMCP

KB_DIR = Path(os.environ.get("FAILURE_KB_DIR", ".failure-kb"))
DB = KB_DIR / "kb.sqlite3"
ARTIFACT_DIR = Path(os.environ.get("FAILURE_KB_ARTIFACTS", ".failure-kb/artifacts"))
SCHEMA_VERSION = 1
CHANGE_SUMMARY_VERSION = 1
MAX_DEPTH = 4
MAX_NODES = 32
MAX_MATCHES = 5
ENTROPY_THRESHOLD = 4.0      # bits/carácter, candidatos >= 20 caracteres
ENTROPY_MIN_LEN = 20
CHANGE_TYPES = {"code", "config", "dependency", "schema", "infra", "firmware", "docs", "test"}
SEVERITIES = {"info", "warning", "blocker"}

mcp = FastMCP("dfiu")


# ---------- errores estructurados ----------
class KBError(Exception):
    def __init__(self, code: str, message: str, fields: list[str] | None = None):
        super().__init__(message)
        self.code, self.message, self.fields = code, message, fields or []

    def to_dict(self) -> dict[str, Any]:
        return {"ok": False, "error": {"code": self.code, "message": self.message,
                                       "fields": self.fields}}


def tool_guard(fn):
    """Convierte KBError y fallos inesperados en el formato de error estándar."""
    import functools

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except KBError as e:
            return e.to_dict()
        except sqlite3.IntegrityError:
            return KBError("conflict", "Violación de integridad").to_dict()
        except Exception:  # no exponer trazas, rutas ni SQL
            return KBError("internal", "Error interno").to_dict()
    return wrapper


# ---------- utilidades ----------
def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def canonical_json(obj: Any, indent: int | None = None) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, indent=indent,
                      separators=(",", ": ") if indent else (",", ":"))


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def bounded(name: str, value: str, limit: int) -> str:
    if len(value) > limit:
        raise KBError("too_large", f"{name} excede {limit} caracteres", [name])
    return value


# ---------- secretos (capa de servicio, antes de persistir y al responder) ----------
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


def shannon(s: str) -> float:
    counts = {ch: s.count(ch) for ch in set(s)}
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def redact(text: str) -> tuple[str, list[str]]:
    """Redacta coincidencias de alta confianza; devuelve (texto, tipos_detectados).
    Idempotente: el marcador no vuelve a coincidir."""
    found: list[str] = []
    for kind, pat in SECRET_PATTERNS:
        def sub(m: re.Match[str], kind: str = kind) -> str:
            found.append(kind)
            if kind == "assignment":
                return f"{m.group(1)}=[REDACTED:secret:assignment]"
            if kind == "auth_header":
                return f"{m.group(1)}: [REDACTED:secret:auth_header]"
            return f"[REDACTED:secret:{kind}]"
        text = pat.sub(sub, text)
    return text, sorted(set(found))


def low_confidence_candidates(text: str) -> int:
    """Cuenta cadenas de alta entropía no redactadas (no se devuelven ni registran)."""
    clean = REDACTED.sub("", text)
    return sum(1 for m in CANDIDATE.finditer(clean) if shannon(m.group(0)) >= ENTROPY_THRESHOLD)


def scrub(name: str, value: str, limit: int, warnings: list[str]) -> str:
    value, kinds = redact(bounded(name, value, limit))
    for k in kinds:
        warnings.append(f"{name}: redactado {k}")
    if low_confidence_candidates(value):
        warnings.append(f"{name}: cadena de alta entropía, revisar (no redactada)")
    return value


# ---------- base de datos ----------
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
]


def _open() -> sqlite3.Connection:
    KB_DIR.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB, timeout=5, isolation_level=None)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA busy_timeout=5000")
    c.execute("PRAGMA journal_mode=WAL")
    return c


@contextmanager
def tx() -> Iterator[tuple[sqlite3.Connection, str]]:
    """Una conexión, una transacción IMMEDIATE, un timestamp; siempre cierra."""
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
        raise KBError("idempotency_conflict", "idempotency_key reutilizada con otra petición",
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
        raise KBError("invalid_input", f"Ruta fuera del proyecto: {p}", ["files_touched"])
    s = str(pp)
    return s[2:] if s.startswith("./") else s


def normalize_summary(summary: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Valida ChangeSummaryV1. Devuelve (normalizado, campos_faltantes)."""
    if summary.get("schema_version") != CHANGE_SUMMARY_VERSION:
        raise KBError("unsupported_schema", "schema_version desconocida", ["schema_version"])
    if not isinstance(summary.get("project"), str) or not summary["project"]:
        raise KBError("invalid_input", "project obligatorio", ["project"])
    missing = [f for f in ("services", "files_touched", "change_type") if f not in summary]
    out: dict[str, Any] = {"schema_version": 1, "project": summary["project"]}
    for f in ("services", "files_touched", "change_type", "environment_tags"):
        vals = summary.get(f, [])
        if not isinstance(vals, list) or not all(isinstance(v, str) for v in vals) or len(vals) > 200:
            raise KBError("invalid_input", f"{f} debe ser lista de strings (máx 200)", [f])
        if f == "files_touched":
            vals = [norm_path(v) for v in vals]
        out[f] = sorted(set(vals))
    bad = set(out["change_type"]) - CHANGE_TYPES
    if bad:
        raise KBError("invalid_input", f"change_type inválido: {sorted(bad)}", ["change_type"])
    for f in ("operation", "subsystem", "error_code", "revision", "empty_reason"):
        if summary.get(f) is not None:
            out[f] = bounded(f, str(summary[f]), 200)
    empty = [f for f in ("services", "files_touched", "change_type") if f in summary and not out[f]]
    if empty and not out.get("empty_reason"):
        missing += empty
    return out, sorted(set(missing))


# ---------- gramática condition_json ----------
LIST_FIELDS = {"services", "files_touched", "change_type", "environment_tags"}
SCALAR_FIELDS = {"project", "operation", "subsystem", "error_code", "revision"}
LEAF_OPS = {"eq", "in", "prefix", "exists", "touches_any", "touches_all", "any_in"}
BOOL_OPS = {"all", "any", "not"}


def validate_condition(node: Any, depth: int = 1, count: list[int] | None = None) -> None:
    count = count if count is not None else [0]
    count[0] += 1
    if depth > MAX_DEPTH or count[0] > MAX_NODES:
        raise KBError("invalid_condition", f"Condición excede profundidad {MAX_DEPTH} o {MAX_NODES} nodos")
    if not isinstance(node, dict) or "op" not in node:
        raise KBError("invalid_condition", "Nodo sin 'op'")
    op = node["op"]
    if op in BOOL_OPS:
        args = node.get("args")
        if not isinstance(args, list) or not args or (op == "not" and len(args) != 1):
            raise KBError("invalid_condition", f"'{op}' requiere args válidos")
        if set(node) != {"op", "args"}:
            raise KBError("invalid_condition", "Claves extra en nodo booleano")
        for a in args:
            validate_condition(a, depth + 1, count)
        return
    if op not in LEAF_OPS:
        raise KBError("invalid_condition", f"Operador no permitido: {op}")
    field = node.get("field")
    if field not in LIST_FIELDS | SCALAR_FIELDS:
        raise KBError("invalid_condition", f"Campo no permitido: {field}")
    if op == "exists":
        if set(node) != {"op", "field"}:
            raise KBError("invalid_condition", "exists solo admite field")
        return
    if set(node) != {"op", "field", "value"}:
        raise KBError("invalid_condition", "Nodo hoja requiere op, field, value")
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
        raise KBError("invalid_condition", f"Tipos inválidos para {op}/{field}")


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


# ---------- reglas ----------
def rule_hash(project: str, scope: str, condition: dict, invariant: str, action: str,
              severity: str) -> str:
    return sha256(canonical_json({"project": project, "scope": scope, "condition": condition,
                                  "invariant": invariant, "action": action,
                                  "severity": severity}))


def dependency_fingerprint(paths: list[str], root: Path = Path(".")) -> str:
    """sha256 sobre 'ruta\\0sha256(contenido)\\n' de cada ruta declarada, ordenadas.
    Ruta ausente => 'ruta\\0MISSING'. Directorios no se admiten."""
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
        raise KBError("illegal_transition", f"{rule['status']} -> {to} no permitida", ["status"])
    c.execute(f"UPDATE rules SET status=?, updated_at=?{extra_sql} WHERE id=?",
              (to, t, *extra_args, rule["id"]))
    c.execute("INSERT INTO rule_transitions VALUES(?,?,?,?,?,?,?,?)",
              (str(uuid.uuid4()), rule["id"], rule["status"], to, reason, actor or None,
               rule["revision"], t))


def get_rule(c: sqlite3.Connection, rule_id: str) -> sqlite3.Row:
    row = c.execute("SELECT * FROM rules WHERE id=?", (rule_id,)).fetchone()
    if row is None:
        raise KBError("not_found", "rule_id no encontrado", ["rule_id"])
    return row


def refresh_staleness(c: sqlite3.Connection, project: str, t: str) -> None:
    rows = c.execute("SELECT * FROM rules WHERE project=? AND status='active'", (project,)).fetchall()
    for r in rows:
        reason = None
        if r["valid_until"] and r["valid_until"] <= t:
            reason = "valid_until vencido"
        elif r["review_after"] and r["review_after"] <= t:
            reason = "review_after vencido"
        elif r["dependency_fingerprint"] and \
                dependency_fingerprint(json.loads(r["dependency_paths_json"])) != r["dependency_fingerprint"]:
            reason = "dependencias cambiaron"
        if reason:
            transition(c, r, "stale", reason, "system", t, ", stale_reason=?", (reason,))


# ---------- herramientas ----------
@mcp.tool()
@tool_guard
def record_failure(project: str, title: str, symptom: str, subsystem: str = "",
                   environment: str = "", error_code: str = "", condition_hash: str = "",
                   tags: list[str] | None = None, suspected_cause: str = "",
                   proposed_resolution: str = "", evidence_summary: str = "",
                   proposed_invariant: str = "", proposed_action: str = "",
                   condition: dict[str, Any] | None = None, scope: str = "",
                   severity: str = "warning", idempotency_key: str = "") -> dict:
    """Registra un incidente (open) y opcionalmente una regla en hypothesis."""
    request = {k: v for k, v in locals().items() if k != "idempotency_key"}
    warnings: list[str] = []
    with tx() as (c, t):
        cached = idempotent(c, "record_failure", idempotency_key, request)
        if cached:
            return cached
        tags_s = sorted(set(tags or []))
        incident_id = str(uuid.uuid4())
        c.execute("""INSERT INTO incidents(id,created_at,updated_at,project,subsystem,environment,
            title,symptom,error_code,condition_hash,root_cause,resolution,status,
            evidence_summary,tags_json,sensitivity) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (incident_id, t, t, bounded("project", project, 160), subsystem or None,
             environment or None, scrub("title", title, 240, warnings),
             scrub("symptom", symptom, 2000, warnings), error_code or None,
             condition_hash or None, scrub("suspected_cause", suspected_cause, 1000, warnings) or None,
             scrub("proposed_resolution", proposed_resolution, 1000, warnings) or None, "open",
             scrub("evidence_summary", evidence_summary, 1000, warnings) or None,
             canonical_json(tags_s), "redacted" if any("redactado" in w for w in warnings) else "normal"))
        rule_id = None
        if proposed_invariant or condition:
            missing = [n for n, v in (("proposed_invariant", proposed_invariant),
                                      ("proposed_action", proposed_action),
                                      ("condition", condition), ("scope", scope)) if not v]
            if missing:
                raise KBError("invalid_input", "Regla propuesta incompleta", missing)
            if severity not in SEVERITIES:
                raise KBError("invalid_input", "severity inválida", ["severity"])
            validate_condition(condition)
            inv = scrub("proposed_invariant", proposed_invariant, 200, warnings)
            act = scrub("proposed_action", proposed_action, 200, warnings)
            rule_id = "R-" + uuid.uuid4().hex[:12]
            c.execute("""INSERT INTO rules(id,created_at,updated_at,project,scope,title,invariant,
                condition_json,action,status,severity,content_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (rule_id, t, t, project, scope, title[:240], inv, canonical_json(condition), act,
                 "hypothesis", severity, rule_hash(project, scope, condition, inv, act, severity)))
            c.execute("INSERT INTO incident_rules VALUES(?,?,?)", (incident_id, rule_id, t))
        response = {"ok": True, "incident_id": incident_id, "status": "open", "rule_id": rule_id,
                    "rule_status": "hypothesis" if rule_id else None, "warnings": warnings,
                    "next_step": "verify_resolution"}
        remember(c, "record_failure", idempotency_key, request, response, t)
        return response


@mcp.tool()
@tool_guard
def verify_resolution(incident_id: str, verdict: str, method: str, success_criterion: str,
                      preconditions: dict[str, str], exercised_failing_path: bool,
                      evidence_summary: str, rule_id: str = "", environment: str = "",
                      source_revision: str = "", condition_hash: str = "", reviewer: str = "",
                      idempotency_key: str = "") -> dict:
    """Registra evidencia. Gate: pass solo cuenta con criterio, precondiciones pass y camino ejercitado."""
    request = {k: v for k, v in locals().items() if k != "idempotency_key"}
    if verdict not in {"pass", "fail", "inconclusive"}:
        raise KBError("invalid_input", "verdict inválido", ["verdict"])
    if method not in {"test", "reproduction", "regression", "operator_review"}:
        raise KBError("invalid_input", "method inválido", ["method"])
    if not preconditions or any(v not in {"pass", "fail", "inconclusive", "not_run"}
                                for v in preconditions.values()):
        raise KBError("invalid_input", "preconditions: {nombre: pass|fail|inconclusive|not_run}",
                      ["preconditions"])
    warnings: list[str] = []
    with tx() as (c, t):
        cached = idempotent(c, "verify_resolution", idempotency_key, request)
        if cached:
            return cached
        inc = c.execute("SELECT status FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if inc is None:
            raise KBError("not_found", "incident_id no encontrado", ["incident_id"])
        rule = None
        if rule_id:
            rule = get_rule(c, rule_id)
            linked = c.execute("SELECT 1 FROM incident_rules WHERE incident_id=? AND rule_id=?",
                               (incident_id, rule_id)).fetchone()
            if not linked:
                raise KBError("invalid_input", "rule_id no vinculada al incidente", ["rule_id"])
        pending = sorted(k for k, v in preconditions.items() if v != "pass")
        if not exercised_failing_path:
            pending.append("exercised_failing_path")
        if method == "operator_review":
            pending.append("method: operator_review no basta para pass efectivo")
        if not success_criterion.strip():
            pending.append("success_criterion")
        effective = verdict == "pass" and not pending
        c.execute("""INSERT INTO verification_log(id,incident_id,rule_id,created_at,verdict,method,
            success_criterion,preconditions_json,exercised_failing_path,environment,source_revision,
            condition_hash,evidence_summary,reviewer) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (str(uuid.uuid4()), incident_id, rule_id or None, t, verdict, method,
             scrub("success_criterion", success_criterion, 500, warnings),
             canonical_json(preconditions), int(exercised_failing_path), environment or None,
             source_revision or None, condition_hash or None,
             scrub("evidence_summary", evidence_summary, 2000, warnings), reviewer or None))
        new_inc = inc["status"]
        if effective:
            new_inc = "verified_resolved"
        elif verdict == "fail" and inc["status"] == "verified_resolved":
            new_inc = "reopened"
        if new_inc != inc["status"]:
            c.execute("UPDATE incidents SET status=?, updated_at=? WHERE id=?", (new_inc, t, incident_id))
        rule_status = rule["status"] if rule else None
        if rule is not None and effective:
            c.execute("""UPDATE rules SET verification_count=verification_count+1, last_verified_at=?,
                updated_at=? WHERE id=?""", (t, t, rule_id))
            if rule["status"] == "hypothesis":
                transition(c, rule, "verified", "verify_resolution pass", reviewer, t)
                rule_status = "verified"
        elif rule is not None and verdict == "fail":
            c.execute("UPDATE rules SET confidence=max(0, confidence-0.2), updated_at=? WHERE id=?",
                      (t, rule_id))
        response = {"ok": True, "incident_id": incident_id, "verdict": verdict,
                    "effective_pass": effective, "incident_status": new_inc,
                    "rule_status": rule_status, "pending_requirements": pending,
                    "warnings": warnings}
        remember(c, "verify_resolution", idempotency_key, request, response, t)
        return response


@mcp.tool()
@tool_guard
def activate_rule(rule_id: str, reviewer: str, reason: str, dependency_paths: list[str] | None = None,
                  source_revision: str = "", review_after: str = "", valid_until: str = "",
                  severity: str = "") -> dict:
    """verified|stale -> active. Requiere reviewer y una verificación efectiva posterior al último cambio."""
    if not reviewer or not reason:
        raise KBError("invalid_input", "reviewer y reason obligatorios", ["reviewer", "reason"])
    with tx() as (c, t):
        r = get_rule(c, rule_id)
        if r["status"] not in {"verified", "stale"}:
            raise KBError("illegal_transition", f"{r['status']} -> active no permitida", ["status"])
        last_stale = c.execute("SELECT max(created_at) FROM rule_transitions "
                               "WHERE rule_id=? AND to_status='stale'", (rule_id,)).fetchone()[0]
        if not r["last_verified_at"] or (r["status"] == "stale" and
                                         r["last_verified_at"] <= (last_stale or "")):
            raise KBError("verification_required", "Falta verificación efectiva en el contexto actual",
                          ["verify_resolution"])
        sev = severity or r["severity"]
        if sev not in SEVERITIES:
            raise KBError("invalid_input", "severity inválida", ["severity"])
        paths = sorted(set(norm_path(p) for p in (dependency_paths or [])))
        fp = dependency_fingerprint(paths) if paths else None
        rev = r["revision"] + (1 if r["status"] == "stale" else 0)
        h = rule_hash(r["project"], r["scope"], json.loads(r["condition_json"]), r["invariant"],
                      r["action"], sev)
        transition(c, r, "active", reason, reviewer, t,
                   ", severity=?, revision=?, content_hash=?, dependency_paths_json=?, "
                   "dependency_fingerprint=?, source_revision=?, review_after=?, valid_until=?, "
                   "stale_reason=NULL",
                   (sev, rev, h, canonical_json(paths), fp, source_revision or None,
                    review_after or None, valid_until or None))
        return {"ok": True, "rule_id": rule_id, "status": "active", "revision": rev,
                "content_hash": h, "dependency_fingerprint": fp}


@mcp.tool()
@tool_guard
def deprecate_rule(rule_id: str, reason: str, reviewer: str, evidence_ref: str = "") -> dict:
    """Cualquier estado salvo deprecated -> deprecated. Motivo obligatorio; no borra historia."""
    if not reason or not reviewer:
        raise KBError("invalid_input", "reason y reviewer obligatorios", ["reason", "reviewer"])
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
    md = [f"# Reglas activas: {project}", ""]
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


@mcp.tool()
@tool_guard
def compile_artifacts(project: str, write: bool = True) -> dict:
    """Compila invariants.json (canónico) y active_rules.md en ARTIFACT_DIR (ruta fija)."""
    with tx() as (c, t):
        refresh_staleness(c, project, t)
        js, md, n = build_artifacts(c, project)
        h = sha256(js)
        if write:
            atomic_write(ARTIFACT_DIR / "invariants.json", js)
            atomic_write(ARTIFACT_DIR / "active_rules.md", md)
            c.execute("INSERT OR REPLACE INTO artifact_state VALUES('invariants.json',?,?,?)", (h, n, t))
        return {"ok": True, "project": project, "rule_count": n, "artifact_sha256": h,
                "written": write, "files": ["invariants.json", "active_rules.md"] if write else []}


@mcp.tool()
@tool_guard
def list_active_invariants(project: str, scope: str = "", severity: str = "",
                           limit: int = 50) -> dict:
    """Inventario compacto de reglas activas; hash del artefacto canónico completo del proyecto."""
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


@mcp.tool()
@tool_guard
def preflight_check(summary: dict[str, Any], limit: int = MAX_MATCHES) -> dict:
    """Evalúa un ChangeSummaryV1 contra reglas active (y stale como advertencia)."""
    s, missing_fields = normalize_summary(summary)
    limit = max(1, min(limit, MAX_MATCHES))
    with tx() as (c, t):
        refresh_staleness(c, s["project"], t)
        js, _, _ = build_artifacts(c, s["project"])
        rows = c.execute("""SELECT id,scope,severity,invariant,action,condition_json,status
            FROM rules WHERE project=? AND status IN ('active','stale') ORDER BY scope,id""",
            (s["project"],)).fetchall()
        links = {r["id"]: [x[0] for x in c.execute(
            "SELECT incident_id FROM incident_rules WHERE rule_id=? ORDER BY incident_id LIMIT 3",
            (r["id"],))] for r in rows}
    sev_rank = {"blocker": 0, "warning": 1, "info": 2}
    matches, insufficient, stale_hits = [], set(), []
    for r in rows:
        trace: list[str] = []
        try:
            hit = evaluate(json.loads(r["condition_json"]), s, trace)
        except Missing as m:
            insufficient.add(m.field)
            continue
        if not hit:
            continue
        item = {"rule_id": r["id"], "severity": r["severity"], "invariant": r["invariant"],
                "action": r["action"], "matched": trace, "incident_ids": links[r["id"]]}
        (stale_hits if r["status"] == "stale" else matches).append(item)
    matches.sort(key=lambda m: (sev_rank[m["severity"]], m["rule_id"]))
    missing_all = sorted(set(missing_fields) | insufficient)
    status = "alert" if (matches or stale_hits) else ("insufficient_context" if missing_all else "clear")
    return {"ok": True, "status": status, "matches": matches[:limit],
            "stale_matches": [{"rule_id": m["rule_id"], "invariant": m["invariant"],
                               "note": "requiere revalidación"} for m in stale_hits[:limit]],
            "evaluated": len(rows), "missing_fields": missing_all,
            "artifact_sha256": sha256(js), "next_tool": "get_incident_details" if matches else None}


SECTIONS = {"summary": ("title", "symptom", "error_code", "status", "subsystem", "environment"),
            "cause": ("root_cause",), "resolution": ("resolution",),
            "references": ("evidence_summary", "evidence_ref")}


@mcp.tool()
@tool_guard
def get_incident_details(incident_id: str, sections: list[str] | None = None,
                         max_chars: int = 2000) -> dict:
    """Detalle acotado de un incidente por id exacto; siempre redactado."""
    sections = sorted(set(sections or ["summary", "cause", "resolution", "verification"]))
    bad = set(sections) - set(SECTIONS) - {"verification"}
    if bad:
        raise KBError("invalid_input", f"sections inválidas: {sorted(bad)}", ["sections"])
    max_chars = max(200, min(max_chars, 8000))
    c = _open()
    try:
        row = c.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if row is None:
            raise KBError("not_found", "incident_id no encontrado", ["incident_id"])
        logs = c.execute("""SELECT verdict,method,created_at,evidence_summary FROM verification_log
            WHERE incident_id=? ORDER BY created_at DESC LIMIT 5""", (incident_id,)).fetchall()
    finally:
        c.close()
    restricted = row["sensitivity"] == "restricted"
    out: dict[str, Any] = {"ok": True, "incident_id": incident_id, "sensitivity": row["sensitivity"]}
    for sec in sections:
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


if __name__ == "__main__":
    migrate()
    mcp.run(transport="stdio")
```

Notas de diseño del código:
- `tx()` garantiza una conexión, una transacción y un timestamp por operación, y cierra siempre (corrige la fuga de conexiones de la v1, donde `with sqlite3.connect()` solo hacía commit).
- `tool_guard` traduce cualquier excepción al formato de error estándar.
- La obsolescencia se refresca de forma perezosa en las herramientas de lectura del proyecto; no hay procesos en segundo plano.

## 12. Suite mínima reproducible de tests

Fixtures pequeñas, sin secretos reales, con timestamps y UUID fijos (inyectar `now()` y generador de ids), base SQLite temporal y directorio de artefactos temporal.

1. **Determinismo del compilador**: misma base → `invariants.json`, `active_rules.md` y `artifact_sha256` byte-idénticos en N ejecuciones; claves y reglas en orden canónico; cambio semántico cambia el hash; ningún campo volátil.
2. **Gramática**: cada operador (coincide/no coincide); `touches_all` con ambos archivos, con uno solo y con arrays vacíos; `not`; profundidad 5 y 33 nodos rechazados; claves extra, clases `[]` y tipos incorrectos → `invalid_condition`.
3. **Contrato `ChangeSummaryV1`**: `schema_version` desconocida → `unsupported_schema`; campos obligatorios ausentes o vacíos sin `empty_reason` → nunca `clear`; rutas `./a`, `a\\b` normalizadas; `..` y absolutas rechazadas; orden de `matches` estable.
4. **Gate de verificación**: pass con precondición `not_run`, sin `exercised_failing_path`, con `operator_review` o sin criterio → `effective_pass=false` y estados intactos; pass efectivo → `verified_resolved` y regla `verified`; fail tras resolución → `reopened` y baja `confidence`; `rule_id` no vinculado → error.
5. **Ciclo de vida**: tabla §3.3 completa (cada transición permitida funciona; cada no permitida → `illegal_transition`); cambio en un archivo de `dependency_paths` → `stale`; `valid_until` vencido → `stale`; reactivar sin nueva verificación → `verification_required`; reactivar tras verificación incrementa `revision`; `deprecated` no se compila.
6. **Herramientas nuevas**: `activate_rule` sin `reviewer` → error; `deprecate_rule` dos veces → `illegal_transition`; `compile_artifacts(write=false)` no escribe archivos; escritura atómica (sin `.tmp` residual).
7. **Idempotencia**: misma clave y request → misma respuesta y una sola fila; clave reutilizada con request distinto → `idempotency_conflict`.
8. **Seguridad**: un caso por tipo del catálogo §7 (sintético) redactado en DB y salidas; cadena de alta entropía no secreta → solo warning; redacción idempotente; `restricted` limita `get_incident_details`; los warnings no contienen el valor.
9. **Errores**: forzar una excepción interna → `{"ok":false,"error":{"code":"internal",...}}` sin traza.
10. **End-to-end**: `record_failure` → `verify_resolution` → `activate_rule` → `preflight_check` (alert) → `compile_artifacts` ×2 (hash igual) → modificar dependencia → `preflight_check` (stale_matches) → `deprecate_rule` → compilado sin la regla. Sin red (bloquear sockets en el test).

---

## Anexo: Fase 2 (no bloquea el MVP)

Resumen de las secciones 10–20 de la v1. Cada punto requiere su propia migración (`user_version` + 1), sus tests y no puede relajar las reglas del núcleo (§2–§9): sin red, sin LLM, sin activación automática y con evidencia append-only.

**A1. Diagnóstico diferencial (v1 §10, §12, §13).** Árboles auditables (`diagnostic_trees`, `hypotheses`, `verification_checks` inmutables con `supersedes_check_id`, `diagnostic_edges` acíclicos). Herramientas: `find_symptom_precedents`, `start_differential_diagnosis`, `get_diagnostic_step`, `record_verification_check`, `pre_mutation_review` (solo evaluación; no autoriza ni ejecuta). Principios: `not_run` nunca descarta; un checksum válido solo descarta lo que ese checksum comprueba; orden de hipótesis por puntuación determinista documentada.

**A2. Memoria relacional (v1 §11).** `symptom_signatures`, `incident_symptoms` (N:M), `causal_links` tipados con evidencia. Grafo en SQLite, sin base de grafos.

**A3. Búsqueda (v1 §14).** Primero FTS5/BM25 local con tokenizer fijado y top-K pequeño (`search_diagnostic_knowledge`). Embeddings solo como extensión opcional local, desactivada por defecto, sin descargas automáticas y fuera de toda ruta determinista: nunca activan reglas ni cierran hipótesis, y no forman parte de los tests de contrato.

**A4. Deduplicación conservadora (v1 §15).** `possible_duplicate` en vez de fusión automática; `merge_events` reversibles; `recurrence_count` vs `observation_count`; `rule_refutations` como vía de deprecación basada en evidencia.

**A5. Anti-hubris ampliado (v1 §16).** Estados `diagnosing`, `change_proposed`, `verification_pending`, `closed_with_residual_risk`; `check_category` (precondition, reproduction, falsification, regression, observation_window, side_effect), ventanas de observación y `challenge_resolution`. El MVP ya implementa el núcleo del gate (§8.2).

**A6. Perfiles de dominio (v1 §17, §19).** `domain_profiles`/`project_profiles` versionados; perfil `firmware_reverse_engineering` con `target_artifacts`, `memory_regions` (rangos hex `[start,end)`, validación de solapamiento en `BEGIN IMMEDIATE`) y `reverse_engineering_notes` (`disputed` en lugar de borrar).

**A7. Context Anchoring (v1 §18).** `environment_state`, `target_resource`, `triggering_action` y `observed_outcome` obligatorios en `record_failure` (con `allow_incomplete` para borradores excluidos de reglas); `context_anchor_json` versionado.

**A8. Presupuesto de tokens (v1 §20).** En el MVP ya rige invariante de una línea ≤200 caracteres. Fase 2: conteo con tokenizer local versionado (objetivo ≤20, máximo 25 tokens), `max_response_bytes` y límites de snippet.

**A9. Secretos ampliados.** Allowlist y pragmas inline con motivo, expiración y auditoría; nunca aplicables a los tipos de alta confianza.
