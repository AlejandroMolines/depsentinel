[Español](SECURITY.es.md) | **English**

# Security policy

## How to report a vulnerability

**Do not open a public issue.** Use this repository's
[private GitHub security advisory](https://github.com/AlejandroMolines/depsentinel/security/advisories/new). Include the
version (`depsentinel version`), the steps to reproduce and the impact you see.

Goal: acknowledge within 3 days and publish the fix and the advisory as soon as it is ready, crediting you if you wish.

## What we consider a vulnerability

* Code execution or file writes beyond what is expected when analyzing a tampered lockfile, Dockerfile or workflow
  (the program reads files that may come from third parties).
* Flaws in the signature or hash verification of the database feed (`db update`).
* Information leaks beyond what the privacy section of the README documents.
* HTML dashboard content that lets a report's data run scripts (XSS).
* Problems in the Action, the release workflow or the publishing chain.

DepSentinel **not detecting** a specific malicious package is a coverage bug, not a vulnerability: open a regular
issue (or a PR adding the entry to `db/malicious.json`, see CONTRIBUTING.es.md).

## How the project protects itself

* **No third-party Go dependencies**: only the standard library. There is no dependency tree to watch.
* Every release ships binaries with `SHA256SUMS` and a provenance attestation (see `docs/installation.md`).
* Built with `-trimpath` and no build ID, to help reproducible builds.
* The database feed is signed with Ed25519; the client verifies the index signature and each file's hash.
* The HTML dashboard ships a CSP that prevents loading or sending anything outside the file.
* CI scans the repository itself with DepSentinel and Dependabot keeps actions and the base image up to date.

## Supported versions

Only the latest minor version receives security fixes while the project is 0.x.
