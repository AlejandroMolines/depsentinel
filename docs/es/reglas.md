**Español** | [English](../rules.md)

# Reglas, configuración y referencia

Cada hallazgo tiene un **identificador de regla** (`rule`), una **severidad** (`low`, `medium`, `high`, `critical`),
un título, una explicación y una forma de arreglarlo. En JSON también incluye `id` (el del aviso, por ejemplo
`GHSA-…`, o el de la comprobación, `DS-…`), `references` y `fixed_in` cuando hay versión corregida.

Desactiva una regla en `.depsentinel.json`: `"disabled_rules": ["typosquat"]`. Los nombres desconocidos se rechazan.

## Paquetes y dependencias

| Regla | Ecosistemas | Severidad | Qué hace saltar el aviso |
|---|---|---|---|
| `malicious` | todos | crítica (`malware`, `compromised`); alta (`sabotage`, `protestware`) | OSV (`MAL-*` o «Malware in …») o la base local firmada. Cómo arreglarlo: eliminar, reinstalar desde cero y **rotar credenciales** |
| `vulnerability` | npm, PyPI, Go, Actions | según CVSS v3 o la etiqueta de GitHub; `medium` si no hay dato | Aviso de OSV que afecta a la versión instalada. Agrupa alias (GHSA, CVE, PYSEC…) y propone la menor versión corregida posterior |
| `typosquat` | npm, PyPI, Go, Docker, Actions | media (directa), baja (transitiva); sube a alta si además ejecuta scripts, es solo código fuente o es muy reciente | Nombre a distancia de edición 1 de uno popular (o solo cambian separadores, o `+js`). No se marca si el paquete tiene 10 o más versiones, más de 2 años de antigüedad o más de 3 años sin tocarse |
| `install-script` | npm | baja | El paquete ejecuta `preinstall`/`install`/`postinstall` y no hay patrones peligrosos. Los paquetes con scripts esperables (esbuild, sharp, …) están en una lista integrada y no avisan |
| `suspicious-script` | npm | crítica/alta/media según el indicio | Patrones peligrosos en el comando: `curl … \| sh`, PowerShell codificado, shells inversas, mineros, exfiltración (webhook.site, IPs públicas…), acceso a credenciales, ofuscación. Con `--deep`, también en el código que esos scripts ejecutan. Sube a crítica si coincide con cambio de publicador |
| `unmaintained` | npm, PyPI, Go | baja | Sin versiones desde hace más de `unmaintained_days` (730). En paquetes transitivos solo si además hay vulnerabilidades |
| `deprecated` | npm | baja; media si el mensaje habla de seguridad | Versión marcada como deprecada. En transitivos solo si es de seguridad |
| `yanked` | PyPI | media | Versión retirada por el mantenedor |
| `fresh-release` | npm, PyPI, Go | baja | Versión publicada hace menos de `min_release_age_hours` (72) |
| `provenance` | npm | baja–alta | Cambio de publicador y/o mantenedores nuevos frente a la versión anterior, solo si la versión se publicó en los últimos 180 días; sube si es muy reciente o tiene scripts de instalación |
| `version-anomaly` | npm, PyPI | alta; media | El paquete o la versión no existen en el registry público (alta); versiones `99.x`/`9999.x` típicas de dependency confusion (media) |
| `unpinned` | PyPI | baja | Requisito sin versión exacta: no se pueden consultar avisos |
| `source` | npm, PyPI, Go | media; alta si es HTTP | Dependencia desde git/URL/tarball externo, `replace` remoto en `go.mod` |
| `index-url` | PyPI | media; alta si es HTTP | `--extra-index-url` (dependency confusion), `--trusted-host`, índice sin cifrar |
| `integrity` | npm | baja; crítica con `--deep` | Entrada de lockfile sin hash; o el tarball descargado no coincide con el hash del lockfile |

## Dockerfiles y compose

| Regla | Severidad | Aviso |
|---|---|---|
| `image-tag` | media | Imagen sin tag o con `latest` y sin digest |
| `image-digest` | baja | Imagen con tag pero sin digest |
| `remote-script` | alta | `RUN curl … \| sh` (o `wget`, `python`, `bash`…) |
| `remote-add` | media | `ADD https://…` sin verificar |
| `secret-in-image` | alta | `ENV`/`ARG` con nombre de secreto (`PASSWORD`, `TOKEN`, `API_KEY`…) y valor literal |
| `root-user` | baja | La etapa final no declara `USER` o usa `root` |

## GitHub Actions

| Regla | Severidad | Aviso |
|---|---|---|
| `action-pinning` | alta (rama como `main`); media (tag de un tercero); baja (tag de `actions/*` o `github/*`) | La acción no está fijada al SHA de un commit. `depsentinel fix` lo arregla |
| `pwn-request` | alta | `pull_request_target` junto con checkout del código del PR |
| `workflow-injection` | alta | Contexto controlado por terceros (`github.event.pull_request.title`, `github.head_ref`…) usado dentro de `run:`/`script:` |
| `workflow-permissions` | media (`write-all`); baja (sin `permissions`) | Permisos del `GITHUB_TOKEN` demasiado amplios o sin declarar |

## `.depsentinel.json`

| Campo | Por defecto | Significado |
|---|---|---|
| `version` | `1` | Versión del formato |
| `ecosystems` | detectar | Lista de ecosistemas (`npm`, `pypi`, `go`, `docker`, `actions`) o `auto` |
| `fail_on` | `high` | Umbral de `--ci` |
| `include_dev` | `true` | `false` equivale a `--prod-only` |
| `ignore_paths` | `[]` | Rutas o patrones que no se recorren (además de `.git`, `node_modules`, `vendor`, `testdata`…) |
| `allowlist_file` | `.depsentinel/allowlist.json` | Lista blanca |
| `disabled_rules` | `[]` | Reglas apagadas |
| `unmaintained_days` | `730` | Umbral de `unmaintained` (`0` la apaga) |
| `min_release_age_hours` | `72` | Umbral de `fresh-release` (`0` la apaga) |
| `feed_url`, `feed_public_key` | oficial / embebida | Feed de `db update` y su clave pública Ed25519 |
| `network.timeout_seconds` | `20` | Timeout por petición |
| `network.concurrency` | `8` | Peticiones simultáneas (1–64) |
| `network.offline` | `false` | Equivale a `--offline` |

## Lista blanca (`.depsentinel/allowlist.json`)

```json
{
  "version": 1,
  "entries": [
    {"ecosystem": "npm", "name": "@babel/*", "rule": "typosquat", "reason": "monorepo conocido", "added": "2026-10-13", "expires": "2027-06-30"}
  ]
}
```

`ecosystem` (`*` = cualquiera), `name` (admite patrones tipo `@scope/*`), `version` (vacío = todas), `rule` (nombre de
regla o ID de aviso; vacío = todas salvo `malicious`), `reason` (**obligatorio**) y `expires` (`AAAA-MM-DD`).

## Variables de entorno

| Variable | Efecto |
|---|---|
| `DEPSENTINEL_OFFLINE` | Cualquier valor equivale a `--offline` |
| `DEPSENTINEL_CACHE_DIR` | Directorio de caché |
| `DEPSENTINEL_OSV_URL`, `_NPM_URL`, `_PYPI_URL`, `_GOPROXY_URL`, `_GITHUB_API_URL`, `_FEED_URL` | Sustituyen los servicios por espejos internos (o servidores de prueba) |
| `DEPSENTINEL_REPORT_URL` | Enlace al informe completo que se añade al comentario de PR |
| `NO_COLOR`, `FORCE_COLOR`, `COLUMNS` | Colores y ancho de la tabla |
| `GITHUB_TOKEN` / `GH_TOKEN` | Solo para `fix`: sube el límite de la API de GitHub |

## Códigos de salida

`0` correcto · `1` hay hallazgos con severidad igual o superior a `--fail-on` (y dentro de `--only`) · `2` uso
incorrecto o configuración inválida · `3` análisis incompleto con `--strict`, o error de ejecución.

Si una fuente de datos no está disponible (por ejemplo OSV), el escaneo continúa con las reglas locales, lo indica en
los avisos y marca el informe como `incomplete`. Con `--strict` ese caso falla.
