[Español](../instalacion.md) | **English**

# Installation

## With Go (recommended)

```bash
go install github.com/AlejandroMolines/depsentinel/cmd/depsentinel@latest
depsentinel version
```

Requires Go 1.22 or later. The binary lands in `$(go env GOPATH)/bin`; make sure it is on your `PATH`.
For a specific version: `...@v1.0.0`.

## With Docker

```bash
docker run --rm -v $(pwd):/src depsentinel/depsentinel scan /src
```

The image is minimal (`distroless`) and runs as a non-root user. To write reports into the mounted directory, run
it with your own user: `docker run --rm --user $(id -u):$(id -g) -v $(pwd):/src depsentinel/depsentinel scan /src -o /src/report.json --format json`.

## Release binaries

Every release publishes binaries for Linux, macOS and Windows (amd64 and arm64, except Windows), a `SHA256SUMS`
file and a provenance attestation signed by GitHub.

```bash
# 1) check the checksum
sha256sum --check --ignore-missing SHA256SUMS

# 2) check the provenance (who built it, and how)
gh attestation verify depsentinel_v1.0.0_linux_amd64 --owner AlejandroMolines
```

## From source

```bash
git clone https://github.com/AlejandroMolines/depsentinel && cd depsentinel
make build          # ./depsentinel
make install        # into $GOBIN
```

## Updating the database

DepSentinel works without downloading anything (OSV on every scan plus the embedded seed). For the extended feed:

```bash
depsentinel db update      # verifies the Ed25519 signature before using it
depsentinel db status      # shows version, age and source
```

To keep it fresh, schedule it. With cron (every day at 6:00):

```cron
0 6 * * * /usr/local/bin/depsentinel db update >/dev/null 2>&1
```

In CI, the Action supports `update-db: "true"` once the feed and its public key are configured.

## Where it stores things

* Cache (OSV advisories, registry metadata, feed): the user cache directory (`~/.cache/depsentinel` on Linux).
  Change it with `DEPSENTINEL_CACHE_DIR`. Clear it with `depsentinel db clean`.
* Configuration and allowlist: inside the project (`.depsentinel.json`, `.depsentinel/allowlist.json`).

## Uninstall

Delete the binary and the cache directory. DepSentinel installs no services and leaves no processes behind.
