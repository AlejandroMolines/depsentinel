[Español](README.es.md) | **English**

# DepSentinel

[![CI](https://github.com/AlejandroMolines/depsentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/AlejandroMolines/depsentinel/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Scan your dependencies before you install or deploy them.** A free, open-source, local-first tool that blocks
malicious packages, typosquatting, dangerous install scripts, abandoned dependencies and vulnerabilities in
**npm, PyPI, Go, Docker and GitHub Actions**.

An `npm install` runs code from strangers: in a test React project, 19 direct dependencies turned into 1,328
installed packages. DepSentinel checks all of them in seconds, on your machine or in your CI, with no account, no
server of our own and no telemetry. No third-party dependencies: only the Go standard library.

> **Language note.** The website and the documentation are available in English and Spanish. The CLI messages
> (finding titles, explanations and fixes) are in **English**; rule IDs, flags and JSON keys are English.

## Install

```bash
go install github.com/AlejandroMolines/depsentinel/cmd/depsentinel@latest      # Go 1.22 or later
docker run --rm -v $(pwd):/src depsentinel/depsentinel scan /src        # one-off scan, nothing to install
```

Release binaries come with checksums and a provenance attestation
([installation and verification](docs/installation.md)).

## Usage

```bash
depsentinel init                      # creates .depsentinel.json and the allowlist (--workflow adds a CI workflow)
depsentinel scan                      # scan the current directory
depsentinel scan --ecosystem npm --lock package-lock.json
depsentinel scan --format json --output report.json
depsentinel scan --ci --fail-on high  # exit code 1 on high or critical risk
depsentinel audit --only high,critical
depsentinel fix --dry-run             # propose fixes; without --dry-run it applies them
depsentinel allowlist add lodash --reason "reviewed manually"
depsentinel sbom --format cyclonedx --output sbom.json
depsentinel db update                 # update the local database (signed feed)
depsentinel report --html --open      # HTML dashboard with the detail of every package
```

Sample output (abridged, fictional project; messages are in Spanish for now):

```
DepSentinel 0.1.0 · ~/tienda-online
npm, Docker, GitHub Actions · 1328 paquetes · 4 manifiestos

SEVERIDAD  PAQUETE                       REGLA           DETALLE
crítico    npm event-stream@3.3.6        malicious       Versión comprometida conoc…
crítico    npm minimist@1.2.0            vulnerability   Prototype Pollution in min…
alto       actions some-org/deploy@main  action-pinning  Acción fijada a una rama m…
alto       docker node:latest            remote-script   Se descarga y ejecuta un s…
alto       npm lodash@4.17.15            vulnerability   Command Injection in lodas…
medio      npm reactt@1.0.0              typosquat       Posible typosquatting de «…
bajo       npm core-js@3.30.2            install-script  Ejecuta scripts al instala…

Resumen: 1328 paquetes · 2 críticos · 3 altos · 1 medio · 1 bajo
Riesgo global: CRÍTICO
✖ 5 hallazgos de severidad alto o superior: el build falla.
```

(`crítico` = critical, `alto` = high, `medio` = medium, `bajo` = low.)

**Exit codes:** `0` OK · `1` findings at or above the threshold · `2` bad usage or invalid configuration ·
`3` incomplete analysis with `--strict`, or a runtime error.

## What it detects

| Rule | What it looks for |
|---|---|
| `malicious` | Known malicious or compromised packages: OSV/OpenSSF `MAL-*` advisories plus a signed local database that works offline |
| `typosquat` | Names almost identical to popular ones (`reactt`, `lodassh`, `reqeusts`), tuned with package age and version count |
| `install-script`, `suspicious-script` | `preinstall`/`install`/`postinstall` scripts; with `--deep`, the code they run (remote downloads, reverse shells, credential theft) and the tarball hash against the lockfile |
| `vulnerability` | CVE and GHSA advisories via [OSV](https://osv.dev), with CVSS severity and the fixed version |
| `unmaintained`, `deprecated`, `yanked` | Abandoned, deprecated or yanked packages |
| `provenance`, `version-anomaly`, `fresh-release` | Publisher or maintainer changes in recent versions, `99.x` versions (dependency confusion), packages that no longer exist |
| `source`, `index-url`, `integrity` | Dependencies from git/URL, `replace` in `go.mod`, insecure indexes, lockfiles without hashes |
| `image-tag`, `image-digest`, `remote-script`, `remote-add`, `secret-in-image`, `root-user` | Dockerfiles and compose: `latest` images, `curl \| sh`, secrets in `ENV`/`ARG`, containers running as root |
| `action-pinning`, `pwn-request`, `workflow-injection`, `workflow-permissions` | GitHub Actions: actions not pinned to a SHA, `pull_request_target` checking out the PR, command injection, excessive permissions |

Every finding comes with an explanation and a concrete way to fix it. Full details, severities and how to disable
each rule: [`docs/rules.md`](docs/rules.md).

### What it reads per ecosystem

| Ecosystem | Files | External sources (online only) |
|---|---|---|
| npm | `package-lock.json`, `npm-shrinkwrap.json` (v1, v2, v3, workspaces) | OSV, npm registry |
| PyPI | `requirements*.txt` (with `-r`), `Pipfile.lock`, `poetry.lock`, `uv.lock` | OSV, PyPI |
| Go | `go.mod` (`require`, `replace`) | OSV, module proxy |
| Docker | `Dockerfile*`, `Containerfile`, `docker-compose*.yml`, `compose*.yml` | none (static analysis) |
| GitHub Actions | `.github/workflows/*.yml`, composite actions | OSV (exact semver tags only) |

## In CI

```yaml
- uses: AlejandroMolines/depsentinel/action@v1
  with:
    fail-on: high
```

The Action builds DepSentinel from the same commit, scans once, comments on the pull request (updating the previous
comment instead of duplicating it), writes the job summary and uploads the JSON report and the HTML dashboard as an
artifact. Inputs and outputs: [`action/action.yml`](action/action.yml). If the action lives in another repository,
pin the version with `version: v1.0.0`.

Without the Action: `depsentinel scan --ci --fail-on high` emits GitHub annotations on the PR and returns the exit code.

## Allowlist with justification

```bash
depsentinel allowlist add lodash --reason "reviewed manually"
depsentinel allowlist add @babel/core --rule typosquat --ecosystem npm --reason "known monorepo" --expires 2027-06-30
depsentinel allowlist list
```

Stored in `.depsentinel/allowlist.json` (commit it: your team and your CI see it). **Every exception requires a
reason.** Expired entries stop applying and raise a warning. A known malicious package can only be allowed with an
explicit exception for the `malicious` rule and the exact version; a generic exception never hides it.

## Configuration

`depsentinel init` creates `.depsentinel.json` (unknown fields are rejected so typos do not go unnoticed):

```json
{
  "version": 1,
  "fail_on": "high",
  "include_dev": true,
  "allowlist_file": ".depsentinel/allowlist.json",
  "unmaintained_days": 730,
  "min_release_age_hours": 72,
  "disabled_rules": [],
  "ignore_paths": [],
  "network": { "timeout_seconds": 20, "concurrency": 8, "offline": false }
}
```

## SBOM and dashboard

* `depsentinel sbom --format cyclonedx` generates a CycloneDX 1.5 SBOM (validated against the official schema) with
  PURLs, integrity hashes and the dependency graph.
* `depsentinel report --html --open` opens a self-contained dashboard (no server, no network requests): overall risk,
  filters, per-package detail (score, use/update/review/avoid recommendation, maintainers, scripts), scan history and
  local false-positive marking with the allowlist command ready to copy. It also opens any report with
  `--input report.json`. The dashboard UI is in Spanish for now, like the CLI.

## Privacy

Online, only the **name and version of each public package** leave your machine, to `api.osv.dev`, and the
**name** to `registry.npmjs.org`, `pypi.org` or `proxy.golang.org`. Never your code, your full lockfile, paths,
tokens or environment variables. Packages installed from git, local paths or URLs are not looked up externally.
`--offline` opens no connection; `--no-osv` and `--no-registry` switch each source off; `DEPSENTINEL_OSV_URL` and
friends point to internal mirrors. The only commands that reach other places are `db update` (downloads the feed) and
`fix` (queries `api.github.com` to resolve an action's SHA).

## Local database

OSV is the main source on every scan. There is also an embedded seed (`db/malicious.json`, `db/popular.json`) that
detects the best-known cases offline. `depsentinel db update` downloads an extended feed and **verifies an Ed25519
signature** of the index and the hash of each file before using it; without a configured public key it refuses to
continue (`--allow-unsigned` at your own risk). How to sign the feed: [`docs/architecture.md`](docs/architecture.md).

## Known limitations

* npm only reads `package-lock.json` and `npm-shrinkwrap.json` (no `yarn.lock` or `pnpm-lock.yaml` yet).
* For PyPI only what appears in the files is evaluated; `requirements.txt` does not resolve transitive dependencies.
* Docker support is static analysis of Dockerfiles: it does not scan image contents (use Trivy or Grype for that).
* CVSS v4 vectors are not scored: the GitHub severity label or `medium` is used.
* Script analysis is static and heuristic: it catches the usual patterns, it is not a review or a sandbox.
* Typosquatting is heuristic and can produce false positives: that is what the allowlist with justification is for.
* CLI messages and the dashboard UI are in Spanish; the website and the docs are bilingual.

## Development

```bash
make check      # format, vet, race tests and feed validation (same as CI)
make build      # ./depsentinel
make dist       # binaries for linux/darwin/windows + SHA256SUMS
```

Structure, how to add a rule or an ecosystem, and the threat model: [`docs/architecture.md`](docs/architecture.md).
Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md). Security: [`SECURITY.md`](SECURITY.md).

## Before publishing

The repository uses `AlejandroMolines` as a placeholder GitHub username. `scripts/set-owner.sh <your-username>` replaces it
across the project. The full checklist (signing keys, GitHub Pages, donations) is in
[`docs/roadmap.md`](docs/roadmap.md).

## License

[MIT](LICENSE). Donations are optional and never unlock features: [`docs/transparency.md`](docs/transparency.md).
