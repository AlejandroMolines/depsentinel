[Español](../reglas.md) | **English**

# Rules, configuration and reference

Every finding has a **rule identifier** (`rule`), a **severity** (`low`, `medium`, `high`, `critical`), a title, an
explanation and a way to fix it. In JSON it also carries `id` (the advisory's, e.g. `GHSA-…`, or the check's,
`DS-…`), `references` and `fixed_in` when a fixed version exists. The text of titles, explanations and fixes is
currently in Spanish; the identifiers below are stable.

Disable a rule in `.depsentinel.json`: `"disabled_rules": ["typosquat"]`. Unknown names are rejected.

## Packages and dependencies

| Rule | Ecosystems | Severity | What triggers it |
|---|---|---|---|
| `malicious` | all | critical (`malware`, `compromised`); high (`sabotage`, `protestware`) | OSV (`MAL-*` or "Malware in …") or the signed local database. Fix: remove, reinstall from scratch and **rotate credentials** |
| `vulnerability` | npm, PyPI, Go, Actions | per CVSS v3 or GitHub's label; `medium` if there is no data | An OSV advisory affecting the installed version. Merges aliases (GHSA, CVE, PYSEC…) and proposes the lowest fixed version above yours |
| `typosquat` | npm, PyPI, Go, Docker, Actions | medium (direct), low (transitive); rises to high if it also runs scripts, ships source only or is very recent | A name at edit distance 1 from a popular one (or only separators differ, or `+js`). Not flagged if the package has 10+ versions, is older than 2 years, or has been untouched for 3+ years |
| `install-script` | npm | low | The package runs `preinstall`/`install`/`postinstall` and no dangerous patterns were found. Packages with expected scripts (esbuild, sharp, …) are in a built-in list and do not warn |
| `suspicious-script` | npm | critical/high/medium by indicator | Dangerous patterns in the command: `curl … \| sh`, encoded PowerShell, reverse shells, miners, exfiltration (webhook.site, public IPs…), credential access, obfuscation. With `--deep`, also in the code those scripts run. Becomes critical when it coincides with a publisher change |
| `unmaintained` | npm, PyPI, Go | low | No releases for more than `unmaintained_days` (730). For transitive packages only if there are also vulnerabilities |
| `deprecated` | npm | low; medium if the message mentions security | Version marked deprecated. For transitive packages only if security-related |
| `yanked` | PyPI | medium | Version yanked by the maintainer |
| `fresh-release` | npm, PyPI, Go | low | Version published less than `min_release_age_hours` (72) ago |
| `provenance` | npm | low–high | Publisher change and/or new maintainers versus the previous version, only if the version was published in the last 180 days; rises if very recent or if it has install scripts |
| `version-anomaly` | npm, PyPI | high; medium | The package or the version does not exist in the public registry (high); `99.x`/`9999.x` versions typical of dependency confusion (medium) |
| `unpinned` | PyPI | low | A requirement without an exact version: advisories cannot be looked up |
| `source` | npm, PyPI, Go | medium; high if HTTP | Dependency from git/URL/external tarball, remote `replace` in `go.mod` |
| `index-url` | PyPI | medium; high if HTTP | `--extra-index-url` (dependency confusion), `--trusted-host`, unencrypted index |
| `integrity` | npm | low; critical with `--deep` | Lockfile entry without a hash; or the downloaded tarball does not match the lockfile hash |

## Dockerfiles and compose

| Rule | Severity | Warning |
|---|---|---|
| `image-tag` | medium | Image with no tag or with `latest`, and no digest |
| `image-digest` | low | Image with a tag but no digest |
| `remote-script` | high | `RUN curl … \| sh` (or `wget`, `python`, `bash`…) |
| `remote-add` | medium | `ADD https://…` without verification |
| `secret-in-image` | high | `ENV`/`ARG` with a secret-like name (`PASSWORD`, `TOKEN`, `API_KEY`…) and a literal value |
| `root-user` | low | The final stage declares no `USER` or uses `root` |

## GitHub Actions

| Rule | Severity | Warning |
|---|---|---|
| `action-pinning` | high (a branch such as `main`); medium (a third party's tag); low (a tag of `actions/*` or `github/*`) | The action is not pinned to a commit SHA. `depsentinel fix` fixes it |
| `pwn-request` | high | `pull_request_target` together with a checkout of the PR's code |
| `workflow-injection` | high | Third-party-controlled context (`github.event.pull_request.title`, `github.head_ref`…) used inside `run:`/`script:` |
| `workflow-permissions` | medium (`write-all`); low (no `permissions`) | `GITHUB_TOKEN` permissions too broad or undeclared |

## `.depsentinel.json`

| Field | Default | Meaning |
|---|---|---|
| `version` | `1` | Format version |
| `ecosystems` | detect | List of ecosystems (`npm`, `pypi`, `go`, `docker`, `actions`) or `auto` |
| `fail_on` | `high` | Threshold for `--ci` |
| `include_dev` | `true` | `false` is the same as `--prod-only` |
| `ignore_paths` | `[]` | Paths or patterns that are not walked (in addition to `.git`, `node_modules`, `vendor`, `testdata`…) |
| `allowlist_file` | `.depsentinel/allowlist.json` | Allowlist |
| `disabled_rules` | `[]` | Switched-off rules |
| `unmaintained_days` | `730` | Threshold for `unmaintained` (`0` disables it) |
| `min_release_age_hours` | `72` | Threshold for `fresh-release` (`0` disables it) |
| `feed_url`, `feed_public_key` | official / embedded | Feed for `db update` and its Ed25519 public key |
| `network.timeout_seconds` | `20` | Timeout per request |
| `network.concurrency` | `8` | Simultaneous requests (1–64) |
| `network.offline` | `false` | Same as `--offline` |

## Allowlist (`.depsentinel/allowlist.json`)

```json
{
  "version": 1,
  "entries": [
    {"ecosystem": "npm", "name": "@babel/*", "rule": "typosquat", "reason": "known monorepo", "added": "2026-10-13", "expires": "2027-06-30"}
  ]
}
```

`ecosystem` (`*` = any), `name` (supports patterns such as `@scope/*`), `version` (empty = all), `rule` (a rule name or
an advisory ID; empty = all except `malicious`), `reason` (**mandatory**) and `expires` (`YYYY-MM-DD`).

## Environment variables

| Variable | Effect |
|---|---|
| `DEPSENTINEL_OFFLINE` | Any value is the same as `--offline` |
| `DEPSENTINEL_CACHE_DIR` | Cache directory |
| `DEPSENTINEL_OSV_URL`, `_NPM_URL`, `_PYPI_URL`, `_GOPROXY_URL`, `_GITHUB_API_URL`, `_FEED_URL` | Replace the services with internal mirrors (or test servers) |
| `DEPSENTINEL_REPORT_URL` | Link to the full report added to the PR comment |
| `NO_COLOR`, `FORCE_COLOR`, `COLUMNS` | Colors and table width |
| `GITHUB_TOKEN` / `GH_TOKEN` | `fix` only: raises GitHub's API rate limit |

## Exit codes

`0` OK · `1` findings at or above `--fail-on` (and inside `--only`) · `2` bad usage or invalid configuration · `3`
incomplete analysis with `--strict`, or a runtime error.

If a data source is unavailable (for example OSV), the scan continues with the local rules, says so in the warnings
and marks the report as `incomplete`. With `--strict` that case fails.
