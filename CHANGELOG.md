[Español](CHANGELOG.es.md) | **English**

# Changelog

Based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); semantic versioning.

## [0.1.0] — First release

### Added
- CLI: `init`, `scan`, `audit`, `fix`, `allowlist`, `sbom`, `report`, `db`, `version`.
- Ecosystems: npm (lockfile v1/v2/v3), PyPI (requirements, Pipfile.lock, poetry.lock, uv.lock), Go (`go.mod`),
  Docker (Dockerfile and compose) and GitHub Actions.
- Rules: known malware (OSV and local database), typosquatting, install scripts (with `--deep`: tarball inspection and
  hash verification), vulnerabilities with CVSS v3 and fixed version, abandonment/deprecation, provenance and version
  anomalies, insecure sources, Dockerfile and workflow hardening.
- Allowlist with mandatory justification and expiry; known malware requires an explicit exception.
- Outputs: table, JSON, PR Markdown, GitHub annotations, HTML dashboard and CycloneDX 1.5 SBOM.
- GitHub Action (composite) with updatable PR comment, job summary and artifact.
- Local database with embedded seed and Ed25519-signed feed (`db update`, `cmd/dbtool`).
- Public Go API (`pkg/api`).
- Bilingual (Spanish/English) website and documentation; transparency page.
