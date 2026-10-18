**Español** | [English](../roadmap.md)

# Hoja de ruta y lista de lanzamiento

## Plan de 2 semanas: dónde está cada entregable

| Día | Entregable | Dónde está |
|---|---|---|
| 1 | Repo, CLI base, `init` | `cmd/depsentinel`, `internal/cli` |
| 2 | Leer `package-lock.json` | `internal/scanner/npm.go` (v1, v2, v3, workspaces, alias) |
| 3 | Reglas de postinstall y typosquatting | `internal/rules/scripts.go`, `typosquat.go` |
| 4 | Integración con OSV | `internal/osv`, `internal/engine/online.go` |
| 5 | Salida tabla/JSON | `internal/report/table.go`, `json.go` |
| 6 | Lista blanca | `internal/allowlist`, `depsentinel allowlist` |
| 7 | Tests y docs | `*_test.go`, `docs/` |
| 8 | GitHub Action | `action/` |
| 9 | `--ci --fail-on high` | `internal/cli/scan.go` |
| 10 | SBOM CycloneDX | `internal/report/sbom.go` |
| 11 | Landing | `web/landing/index.html` |
| 12 | Donaciones y transparencia | `web/landing/transparencia.html`, `docs/es/transparencia.md` |
| 13 | Docker | `Dockerfile` |
| 14 | Lanzamiento | esta lista |

Además de npm (MVP), ya están PyPI, Go, Docker y GitHub Actions, `fix`, `report --html`, el modo `--deep`, la base de
datos firmada y la API en Go.

## Antes de publicar (una sola vez)

- [ ] `scripts/set-owner.sh <tu-usuario>` y `go build ./... && make check`
- [ ] Crear el repositorio en GitHub, activar **private vulnerability reporting** (Settings → Security)
- [ ] `make db-keygen`, guardar la privada como secreto, pegar la pública en `db/pubkey.txt`, `make db-sign`, commit
- [ ] Crear los enlaces reales de donación (GitHub Sponsors, Open Collective, Ko-fi) y revisar `.github/FUNDING.yml`
- [ ] Activar GitHub Pages con el workflow `pages.yml` (Settings → Pages → Source: GitHub Actions) para `web/landing`
- [ ] Cuando la web tenga su URL definitiva, hacer absolutos los enlaces `hreflang` de las cabeceras HTML
- [ ] Reservar el nombre de la imagen de Docker y publicar `depsentinel/depsentinel`
- [ ] Etiquetar `v0.1.0` (`git tag v0.1.0 && git push --tags`): el workflow `release.yml` publica binarios, sumas y atestación
- [ ] Fijar las acciones de los workflows a un SHA (`depsentinel fix` lo hace) y revisar los permisos
- [ ] Comprobar el nombre definitivo: «DepSentinel» es provisional (conviene buscar colisiones de marca y de paquetes)

## Lanzamiento (día 14)

Orden sugerido: un PR de ejemplo con el comentario de la Action en el propio repositorio, vídeo corto de la demo del
terminal, y después Hacker News («Show HN»), Product Hunt y Reddit (`r/netsec`, `r/devops`, `r/golang`, comunidades de
npm y Python). Mensaje base:

> **Show HN: DepSentinel — scan your dependencies for malicious packages before you install them**
> Open source, free, local-first (Go, zero third-party dependencies). Checks npm, PyPI, Go, Docker and GitHub Actions
> against OSV and a signed local database; flags typosquatting, dangerous install scripts (with `--deep` it downloads the
> tarball, verifies it against the lockfile hash and reads what the scripts execute), CVEs, abandoned packages and
> risky workflows. Comments on PRs and fails CI on high risk. Allowlist entries require a written reason. No account,
> no telemetry; `--offline` opens no connections.

Responde cada comentario técnico con datos y abre un issue por cada falso positivo reportado: es la mejor fuente de mejoras.

## Después del lanzamiento

Métricas a seguir: escaneos por semana (la Action y los descargadores de la release dan una idea), paquetes
maliciosos bloqueados, falsos positivos reportados (y tiempo hasta corregirlos), contribuidores activos, donaciones
recurrentes y proyectos que adoptan la Action.

Ideas pendientes: **mensajes del CLI y del panel en inglés** (catálogo de mensajes y `--lang`/`DEPSENTINEL_LANG`), `yarn.lock` y `pnpm-lock.yaml`, resolución de dependencias transitivas en `requirements.txt` y
`pyproject.toml`, salida SARIF para el escaneo de código de GitHub, comparación entre escaneos (detectar que un tarball
cambió para la misma versión), puntuación CVSS v4, tap de Homebrew y paquetes para las distribuciones.
