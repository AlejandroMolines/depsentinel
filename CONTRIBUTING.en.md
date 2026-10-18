[Español](CONTRIBUTING.md) | **English**

# Contributing to DepSentinel

Thank you! The most useful contributions are usually **false-positive reports**, **malicious packages it misses**
and **real test cases**.

## Set up

```bash
git clone https://github.com/AlejandroMolines/depsentinel && cd depsentinel
make check          # format, vet, race tests and feed validation
make build && ./depsentinel scan . --offline
```

You only need Go 1.22 or later. The project has no external dependencies and should stay that way: use the standard
library unless there is a strong reason (and discuss it in an issue first).

## Ground rules

1. **A new rule comes with tests**: a case that must warn and a similar one that must **not**. False positives cost
   more trust than false negatives.
2. **Every finding explains and proposes**: title, detail and an actionable `Fix`.
3. **External data is untrusted**: package names, deprecation messages and registry responses can come from an
   attacker. Never execute them, interpolate them into commands or render them unescaped (the dashboard uses
   `textContent`).
4. **No network without `--offline`**: every external query goes through `internal/httpx` and honors offline mode.
5. If visible behavior changes, update `docs/en/rules.md` (and its Spanish twin `docs/reglas.md`) or the README.

## Adding known-malicious packages to the database

Edit `db/malicious.json`: unique `id` (`DS-NNNN`), `ecosystem`, `name`, `versions` (`["*"]` = all), `kind`
(`malware`, `compromised`, `sabotage` or `protestware`), `summary` and `reference` (a link to a public source: a
GitHub advisory, an OSV entry, a registry write-up). **Entries without a public source are not accepted.** Validate
with `go run ./cmd/dbtool check -dir db`. Maintainers regenerate the feed signature (`make db-sign`).

## Adding an ecosystem or a rule

See `docs/en/architecture.md`: a parser in `internal/scanner`, rules in `internal/rules`, and tests with real files
reduced to the minimum.

## Language

User-facing messages are currently in Spanish (the CLI) and identifiers (rules, flags, JSON keys) are in English.
Documentation and the website must be kept in both languages: when you change `docs/foo.md`, update `docs/en/…`.
Pull requests that add English CLI messages are very welcome (see the roadmap).

## Style

`gofmt` is mandatory, errors carry context. Small, descriptive commits.

## Conduct

Be kind and assume good faith. Hard technical criticism is welcome; personal attacks are not.
