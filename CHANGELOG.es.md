**Español** | [English](CHANGELOG.md)

# Cambios

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/); versionado semántico.

## [0.1.0] — Primera versión

### Añadido
- CLI: `init`, `scan`, `audit`, `fix`, `allowlist`, `sbom`, `report`, `db`, `version`.
- Ecosistemas: npm (lockfile v1/v2/v3), PyPI (requirements, Pipfile.lock, poetry.lock, uv.lock), Go (`go.mod`),
  Docker (Dockerfile y compose) y GitHub Actions.
- Reglas: malware conocido (OSV y base local), typosquatting, scripts de instalación (con `--deep`: inspección del
  tarball y verificación de su hash), vulnerabilidades con CVSS v3 y versión corregida, abandono/deprecación,
  procedencia y anomalías de versión, orígenes inseguros, endurecimiento de Dockerfiles y workflows.
- Lista blanca con justificación obligatoria y caducidad; el malware conocido exige excepción explícita.
- Salidas: tabla, JSON, Markdown para PR, anotaciones de GitHub, panel HTML y SBOM CycloneDX 1.5.
- GitHub Action (compuesta) con comentario de PR actualizable, resumen del job y artefacto.
- Base de datos local con semilla embebida y feed firmado con Ed25519 (`db update`, `cmd/dbtool`).
- API pública en Go (`pkg/api`).
- Landing, panel y página de transparencia.
