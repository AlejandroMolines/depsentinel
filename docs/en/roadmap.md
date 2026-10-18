[Español](../hoja-de-ruta.md) | **English**

# Roadmap and launch checklist

## The 2-week plan: where each deliverable lives

| Day | Deliverable | Where |
|---|---|---|
| 1 | Repo, base CLI, `init` | `cmd/depsentinel`, `internal/cli` |
| 2 | Read `package-lock.json` | `internal/scanner/npm.go` (v1, v2, v3, workspaces, aliases) |
| 3 | Postinstall and typosquatting rules | `internal/rules/scripts.go`, `typosquat.go` |
| 4 | OSV integration | `internal/osv`, `internal/engine/online.go` |
| 5 | Table/JSON output | `internal/report/table.go`, `json.go` |
| 6 | Allowlist | `internal/allowlist`, `depsentinel allowlist` |
| 7 | Tests and docs | `*_test.go`, `docs/` |
| 8 | GitHub Action | `action/` |
| 9 | `--ci --fail-on high` | `internal/cli/scan.go` |
| 10 | CycloneDX SBOM | `internal/report/sbom.go` |
| 11 | Landing | `web/landing/index.html` and `web/landing/en/index.html` |
| 12 | Donations and transparency | `web/landing/transparencia.html`, `web/landing/en/transparency.html`, `docs/en/transparency.md` |
| 13 | Docker | `Dockerfile` |
| 14 | Launch | this list |

On top of npm (the MVP) there are already PyPI, Go, Docker and GitHub Actions, `fix`, `report --html`, the `--deep`
mode, the signed database and the Go API.

## Before publishing (once)

- [ ] `scripts/set-owner.sh <your-username>` and `go build ./... && make check`
- [ ] Create the GitHub repository and enable **private vulnerability reporting** (Settings → Security)
- [ ] `make db-keygen`, keep the private key as a secret, paste the public key into `db/pubkey.txt`, `make db-sign`, commit
- [ ] Create the real donation links (GitHub Sponsors, Open Collective, Ko-fi) and review `.github/FUNDING.yml`
- [ ] Enable GitHub Pages with the `pages.yml` workflow (Settings → Pages → Source: GitHub Actions) for `web/landing`
- [ ] Once the site has its final URL, make the `hreflang` links in the HTML heads absolute
- [ ] Reserve the Docker image name and publish `depsentinel/depsentinel`
- [ ] Tag `v0.1.0` (`git tag v0.1.0 && git push --tags`): `release.yml` publishes binaries, checksums and attestation
- [ ] Pin the workflows' actions to a SHA (`depsentinel fix` does it) and review permissions
- [ ] Check the final name: "DepSentinel" is provisional (look for trademark and package-name collisions)

## Launch (day 14)

Suggested order: an example PR showing the Action's comment in the repository itself, a short video of the terminal
demo, then Hacker News ("Show HN"), Product Hunt and Reddit (`r/netsec`, `r/devops`, `r/golang`, npm and Python
communities). Base message:

> **Show HN: DepSentinel — scan your dependencies for malicious packages before you install them**
> Open source, free, local-first (Go, zero third-party dependencies). Checks npm, PyPI, Go, Docker and GitHub Actions
> against OSV and a signed local database; flags typosquatting, dangerous install scripts (with `--deep` it downloads the
> tarball, verifies it against the lockfile hash and reads what the scripts execute), CVEs, abandoned packages and
> risky workflows. Comments on PRs and fails CI on high risk. Allowlist entries require a written reason. No account,
> no telemetry; `--offline` opens no connections.

Reply to every technical comment with data and open an issue for each reported false positive: it is the best source
of improvements. Be upfront that CLI messages are Spanish today (the English-speaking audience will ask).

## After the launch

Metrics to follow: scans per week (the Action and release downloads give an idea), malicious packages blocked, false
positives reported (and time to fix them), active contributors, recurring donations and projects adopting the Action.

Pending ideas: **English CLI messages** (a message catalog and a `--lang`/`DEPSENTINEL_LANG` switch, also for the
dashboard), `yarn.lock` and `pnpm-lock.yaml`, transitive resolution for `requirements.txt` and `pyproject.toml`, SARIF
output for GitHub code scanning, comparison between scans (detect that a tarball changed for the same version), CVSS
v4 scoring, a Homebrew tap and distro packages.
