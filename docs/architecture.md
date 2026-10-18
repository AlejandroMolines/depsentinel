[Español](../es/arquitectura.md) | **English**

# Architecture

```
cmd/depsentinel      CLI entry point
cmd/dbtool           maintainer tools: keys, validation and feed signing
pkg/api              public Go API (Scan, UpdateDB)
internal/cli         commands (scan, audit, fix, init, allowlist, sbom, report, db)
internal/engine      orchestration of a scan
internal/scanner     manifest readers (npm, PyPI, Go, Docker, Actions) + static analysis
internal/rules       rules (vulnerabilities, malware, typosquat, scripts, maintenance, provenance)
internal/osv         OSV client, CVSS v3, alias grouping
internal/registry    npm, PyPI, Go proxy and GitHub (+ tarballs and hash verification)
internal/db          embedded seed + signed feed (Ed25519)
internal/allowlist   allowlist with justification
internal/config      .depsentinel.json and endpoints
internal/fix         fix planning and application
internal/report      table, JSON, Markdown, annotations, HTML and CycloneDX SBOM
internal/{model,semver,cache,httpx,workpool,term,version}   shared pieces
db/                  seed (malicious.json, popular.json, allowlist.json) and signed feed
web/                 landing (es/en), transparency and the HTML dashboard embedded in the binary
action/              composite GitHub Action
```

## Flow of a scan

```
Detect (walks the tree, skips node_modules/.git/vendor/testdata)
  → Parse per ecosystem → packages + static findings (Docker, Actions, sources, indexes)
  → merge repeated packages (same name@version in several node_modules)
  → OSV: querybatch (500 per request, paginated) + advisory details (cached by id+modified)
  → registries: abbreviated npm for all and the full document for direct packages and those with scripts;
                PyPI (JSON), Go proxy
  → (--deep) tarballs of packages with scripts: hash against the lockfile + analysis of the code that runs
  → per-package rules → correlation (raises severity when weak signals coincide)
  → deduplication → allowlist → summary and scoring → report
```

Design decisions:

* **Local first.** Any external source can be missing: the scan continues with local rules, says so and marks the
  report as incomplete (`--strict` turns that into an error).
* **Few false alarms.** Weak signals are softened for transitive dependencies, dropped for established packages and
  only rise when combined. The allowlist demands a reason.
* **External data is hostile.** Names and messages coming from registries or lockfiles are never interpreted as
  commands; the HTML dashboard renders everything with `textContent` and is served with a CSP that blocks the network.
* **No dependencies.** Standard library only. That is why the "local database" is embedded JSON (`go:embed`) rather
  than SQLite, and the dashboard is a static file instead of a service with an API: nothing to host or maintain.
* **Bilingual surface.** The website and the documentation exist in Spanish and English. CLI messages are Spanish for
  now; making them translatable (a message catalog instead of literal strings in `internal/rules`, `internal/scanner`,
  `internal/report` and `internal/cli`) is the next step on the roadmap.

## Adding a rule

1. Write `func MyRule(c *Context, p *model.Package) []model.Finding` in `internal/rules`.
2. Call it from `Evaluate` (`internal/rules/rules.go`) and honor `c.enabled("my-rule")`.
3. Add the name to `config.KnownRules` and document severity and fix in `docs/rules.md` (and `docs/es/reglas.md`).
4. Tests: one case that warns and a similar one that does not.

## Adding an ecosystem

1. A constant in `internal/model` (`Ecosystem`, `OSV()` if OSV covers it, `ParseEcosystem`).
2. A parser in `internal/scanner` returning `*Result` (packages and static findings); register it in `Classify`
   (which files) and `Parse`.
3. If there is a public registry: a client in `internal/registry` filling `model.Meta`, and its call in `engine.enrich`.
4. Popular names in `db/popular.json`, and the PURL key in `report.PURL`.

## Signing the database feed

The client only accepts a feed whose `index.json` is signed with the key whose public half is in `db/pubkey.txt`.

```bash
make db-keygen                     # once: prints the public key and saves the private one (mode 0600)
# paste the "public:" line into db/pubkey.txt and rebuild; keep the private key as a secret (DB_SIGNING_KEY)
make db-check                      # validate the files
make db-sign KEY=depsentinel-feed.key   # regenerate db/index.json and db/index.json.sig
make db-verify                     # check the signature and hashes
```

Publish `db/` on the `main` branch: the feed's default URL is that directory's `raw.githubusercontent.com`.
An attacker who can write to the repository but lacks the private key can **not** make clients accept a tampered feed.

## Tests

`make check` runs formatting, `go vet`, all tests with `-race` and the feed validation. The engine and CLI tests use
simulated HTTP servers for OSV and npm (including a tarball with exfiltration), so they need no network.
