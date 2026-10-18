**Español** | [English](en/architecture.md)

# Arquitectura

```
cmd/depsentinel      punto de entrada del CLI
cmd/dbtool           herramientas del mantenedor: claves, validación y firma del feed
pkg/api              API pública en Go (Scan, UpdateDB)
internal/cli         comandos (scan, audit, fix, init, allowlist, sbom, report, db)
internal/engine      orquestación de un escaneo
internal/scanner     lectores de manifiestos (npm, PyPI, Go, Docker, Actions) + análisis estático
internal/rules       reglas (vulnerabilidades, malware, typosquat, scripts, mantenimiento, procedencia)
internal/osv         cliente de OSV, CVSS v3, agrupación de alias
internal/registry    npm, PyPI, proxy de Go y GitHub (+ tarballs y verificación de hashes)
internal/db          semilla embebida + feed firmado (Ed25519)
internal/allowlist   lista blanca con justificación
internal/config      .depsentinel.json y endpoints
internal/fix         plan y aplicación de arreglos
internal/report      tabla, JSON, Markdown, anotaciones, HTML y SBOM CycloneDX
internal/{model,semver,cache,httpx,workpool,term,version}   piezas compartidas
db/                  semilla (malicious.json, popular.json, allowlist.json) y feed firmado
web/                 landing (es/en), transparencia y el panel HTML que se embebe en el binario
action/              GitHub Action compuesta
```

## Flujo de un escaneo

```
Detect (recorre el árbol, salta node_modules/.git/vendor/testdata)
  → Parse por ecosistema → paquetes + hallazgos estáticos (Docker, Actions, orígenes, índices)
  → fusión de paquetes repetidos (mismo nombre@versión en varios node_modules)
  → OSV: querybatch (500 por petición, con paginación) + detalle de avisos (caché por id+modified)
  → registries: npm abreviado para todos y documento completo para directos y con scripts;
                PyPI (JSON), proxy de Go
  → (--deep) tarballs de paquetes con scripts: hash contra el lockfile + análisis del código que se ejecuta
  → reglas por paquete → correlación (sube la severidad si coinciden señales débiles)
  → deduplicación → lista blanca → resumen y puntuación → informe
```

Decisiones de diseño:

* **Local primero.** Cualquier fuente externa puede faltar: el escaneo continúa con reglas locales, lo avisa y marca el
  informe como incompleto (`--strict` lo convierte en error).
* **Pocas falsas alarmas.** Las señales débiles se atenúan en dependencias transitivas, se descartan en paquetes
  consolidados y solo suben de nivel al combinarse. La lista blanca exige motivo.
* **Los datos externos son hostiles.** Los nombres y mensajes que vienen de registries o lockfiles no se interpretan
  nunca como comandos; el panel HTML pinta todo con `textContent` y se sirve con una CSP que impide red.
* **Sin dependencias.** Solo biblioteca estándar. Por eso la «base local» es JSON embebido (`go:embed`) y no SQLite,
  y el panel es un fichero estático en lugar de un servicio con API: nada que alojar ni mantener.

## Añadir una regla

1. Escribe la función `func MiRegla(c *Context, p *model.Package) []model.Finding` en `internal/rules`.
2. Llámala desde `Evaluate` (`internal/rules/rules.go`) y respeta `c.enabled("mi-regla")`.
3. Añade el nombre a `config.KnownRules` y documenta severidad y arreglo en `docs/reglas.md`.
4. Tests: un caso que avisa y uno parecido que no.

## Añadir un ecosistema

1. Constante en `internal/model` (`Ecosystem`, `OSV()` si OSV lo cubre, `ParseEcosystem`).
2. Parser en `internal/scanner` que devuelva `*Result` (paquetes y hallazgos estáticos); regístralo en `Classify`
   (qué ficheros) y `Parse`.
3. Si hay registry público: cliente en `internal/registry` que rellene `model.Meta`, y su llamada en `engine.enrich`.
4. Nombres populares en `db/popular.json`, y la clave PURL en `report.PURL`.

## Firmar el feed de la base de datos

El cliente solo acepta un feed cuyo `index.json` esté firmado con la clave cuyo pública está en `db/pubkey.txt`.

```bash
make db-keygen                     # una vez: imprime la clave pública y guarda la privada (permisos 0600)
# pega la línea "public:" en db/pubkey.txt y recompila; guarda la privada como secreto (DB_SIGNING_KEY)
make db-check                      # valida los ficheros
make db-sign KEY=depsentinel-feed.key   # regenera db/index.json y db/index.json.sig
make db-verify                     # comprueba la firma y los hashes
```

Publica `db/` en la rama `main`: la URL por defecto del feed es el `raw.githubusercontent.com` de ese directorio.
Un atacante que consiga escribir en el repositorio pero no tenga la clave privada **no** puede hacer que los clientes
acepten un feed alterado.

## Tests

`make check` ejecuta formato, `go vet`, todos los tests con `-race` y la validación del feed. Los tests del motor y
del CLI usan servidores HTTP simulados de OSV y de npm (incluido un tarball con exfiltración), así que no necesitan red.
