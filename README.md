**Español** | [English](README.en.md)

# DepSentinel

[![CI](https://github.com/AlejandroMolines/depsentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/AlejandroMolines/depsentinel/actions/workflows/ci.yml)
[![Licencia: MIT](https://img.shields.io/badge/licencia-MIT-blue.svg)](LICENSE)

**Escanea tus dependencias antes de instalar o desplegar.** Herramienta de código abierto, gratuita y local que
bloquea paquetes maliciosos, typosquatting, scripts de instalación peligrosos, dependencias abandonadas y
vulnerabilidades en **npm, PyPI, Go, Docker y GitHub Actions**.

Un `npm install` ejecuta código de desconocidos: en un proyecto React de prueba, 19 dependencias directas se
convirtieron en 1.328 paquetes instalados. DepSentinel los revisa todos en segundos, en tu máquina o en tu CI, sin
cuenta, sin servidor propio y sin telemetría. Sin dependencias de terceros: solo la biblioteca estándar de Go.

## Instalación

```bash
go install github.com/AlejandroMolines/depsentinel/cmd/depsentinel@latest      # Go 1.22 o superior
docker run --rm -v $(pwd):/src depsentinel/depsentinel scan /src        # sin instalar nada
```

También hay binarios con suma de comprobación y atestación de procedencia en cada release
([instalación y verificación](docs/instalacion.md)).

## Uso

```bash
depsentinel init                      # crea .depsentinel.json y la lista blanca (--workflow añade el workflow de CI)
depsentinel scan                      # escanea el directorio actual
depsentinel scan --ecosystem npm --lock package-lock.json
depsentinel scan --format json --output report.json
depsentinel scan --ci --fail-on high  # falla (código 1) si hay riesgo alto o crítico
depsentinel audit --only high,critical
depsentinel fix --dry-run             # propone arreglos; sin --dry-run los aplica
depsentinel allowlist add lodash --reason "revisado manualmente"
depsentinel sbom --format cyclonedx --output sbom.json
depsentinel db update                 # actualiza la base de datos local (feed firmado)
depsentinel report --html --open      # panel HTML con el detalle de cada paquete
```

Salida de ejemplo (abreviada, proyecto ficticio):

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

**Códigos de salida:** `0` correcto · `1` hallazgos sobre el umbral · `2` uso incorrecto o configuración inválida ·
`3` análisis incompleto con `--strict`, o error de ejecución.

## Qué detecta

| Regla | Qué busca |
|---|---|
| `malicious` | Paquetes maliciosos o comprometidos conocidos: avisos `MAL-*` de OSV/OpenSSF y una base local firmada que funciona sin conexión |
| `typosquat` | Nombres casi idénticos a los populares (`reactt`, `lodassh`, `reqeusts`), ajustado con la antigüedad y el número de versiones del paquete |
| `install-script`, `suspicious-script` | Scripts `preinstall`/`install`/`postinstall`; con `--deep`, el código que ejecutan (descargas remotas, shells inversas, robo de credenciales) y el hash del tarball contra el lockfile |
| `vulnerability` | CVE y GHSA vía [OSV](https://osv.dev), con severidad CVSS y la versión que lo corrige |
| `unmaintained`, `deprecated`, `yanked` | Paquetes abandonados, deprecados o retirados |
| `provenance`, `version-anomaly`, `fresh-release` | Cambios de publicador o mantenedores en versiones recientes, versiones `99.x` (dependency confusion), paquetes que ya no existen |
| `source`, `index-url`, `integrity` | Dependencias desde git/URL, `replace` en `go.mod`, índices inseguros, lockfiles sin hash |
| `image-tag`, `image-digest`, `remote-script`, `remote-add`, `secret-in-image`, `root-user` | Dockerfiles y compose: imágenes `latest`, `curl \| sh`, secretos en `ENV`/`ARG`, contenedores como root |
| `action-pinning`, `pwn-request`, `workflow-injection`, `workflow-permissions` | GitHub Actions: acciones sin fijar a un SHA, `pull_request_target` con checkout del PR, inyección de comandos, permisos excesivos |

Cada hallazgo incluye una explicación y una forma concreta de arreglarlo. Detalle completo, severidades y cómo
desactivar cada regla en [`docs/reglas.md`](docs/reglas.md).

### Qué lee de cada ecosistema

| Ecosistema | Ficheros | Fuentes externas (solo con conexión) |
|---|---|---|
| npm | `package-lock.json`, `npm-shrinkwrap.json` (v1, v2 y v3, workspaces) | OSV, registry de npm |
| PyPI | `requirements*.txt` (con `-r`), `Pipfile.lock`, `poetry.lock`, `uv.lock` | OSV, PyPI |
| Go | `go.mod` (`require`, `replace`) | OSV, proxy de módulos |
| Docker | `Dockerfile*`, `Containerfile`, `docker-compose*.yml`, `compose*.yml` | — (análisis estático) |
| GitHub Actions | `.github/workflows/*.yml`, acciones compuestas | OSV (solo etiquetas semver exactas) |

## En CI

```yaml
- uses: AlejandroMolines/depsentinel/action@v1
  with:
    fail-on: high
```

La Action compila DepSentinel desde el mismo commit, escanea una vez, comenta (y actualiza, sin duplicar) el
resultado en el pull request, escribe el resumen del job y sube el informe JSON y el panel HTML como artefacto.
Entradas y salidas en [`action/action.yml`](action/action.yml). Para fijar la versión usa `version: v1.0.0` si la
acción vive en otro repositorio.

Sin la Action: `depsentinel scan --ci --fail-on high` emite anotaciones de GitHub en el PR y devuelve el código de salida.

## Lista blanca con justificación

```bash
depsentinel allowlist add lodash --reason "revisado manualmente"
depsentinel allowlist add @babel/core --rule typosquat --ecosystem npm --reason "monorepo conocido" --expires 2027-06-30
depsentinel allowlist list
```

Se guarda en `.depsentinel/allowlist.json` (haz commit: el equipo y el CI lo ven). **Toda excepción exige un motivo.**
Las caducadas dejan de aplicarse y avisan. Un paquete malicioso conocido solo se puede permitir con una excepción
explícita para la regla `malicious` y la versión exacta; una excepción genérica nunca lo oculta.

## Configuración

`depsentinel init` crea `.depsentinel.json` (los campos desconocidos se rechazan para detectar erratas):

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

## SBOM y panel

* `depsentinel sbom --format cyclonedx` genera un SBOM CycloneDX 1.5 (validado contra el esquema oficial) con PURLs,
  hashes de integridad y grafo de dependencias.
* `depsentinel report --html --open` abre un panel autocontenido (sin servidor ni peticiones de red): riesgo global,
  filtros, detalle por paquete (puntuación, recomendación usar/actualizar/revisar/evitar, mantenedores, scripts),
  historial de escaneos y marcado local de falsos positivos con el comando de lista blanca listo para copiar.
  También abre cualquier informe con `--input report.json`.

## Privacidad

Con conexión, sale de tu máquina únicamente el **nombre y la versión de cada paquete público** hacia `api.osv.dev`
y el **nombre** hacia `registry.npmjs.org`, `pypi.org` o `proxy.golang.org`. Nunca tu código, tu lockfile completo,
rutas, tokens ni variables de entorno. Los paquetes instalados desde git, rutas locales o URLs no se consultan fuera.
`--offline` no abre ninguna conexión; `--no-osv` y `--no-registry` apagan cada fuente; `DEPSENTINEL_OSV_URL` y
compañía apuntan a espejos internos. Los únicos comandos que salen a otros sitios son `db update` (descarga el feed)
y `fix` (consulta `api.github.com` para resolver el SHA de una acción).

## Base de datos local

La fuente principal en cada escaneo es OSV. Además hay una semilla embebida (`db/malicious.json`, `db/popular.json`)
que permite detectar los casos más conocidos sin conexión. `depsentinel db update` descarga un feed ampliado y
**verifica una firma Ed25519** del índice y los hashes de cada fichero antes de usarlo; sin clave pública configurada
se niega a continuar (`--allow-unsigned` bajo tu responsabilidad). Cómo firmar el feed: [`docs/arquitectura.md`](docs/arquitectura.md).

## Límites conocidos

* npm solo lee `package-lock.json` y `npm-shrinkwrap.json` (no `yarn.lock` ni `pnpm-lock.yaml` todavía).
* En PyPI solo se evalúa lo que aparece en los ficheros; `requirements.txt` no resuelve dependencias transitivas.
* Docker es análisis estático de Dockerfiles: no escanea el contenido de las imágenes (usa Trivy o Grype para eso).
* Los vectores CVSS v4 no se puntúan: se usa la etiqueta de severidad de GitHub o `medium` por defecto.
* El análisis de scripts es estático y heurístico: detecta lo habitual, no sustituye una revisión ni un sandbox.
* El typosquatting es heurístico y puede dar falsos positivos: para eso está la lista blanca con justificación.
* Los mensajes del CLI y la interfaz del panel están en castellano; la web y la documentación tienen versión en inglés ([README.en.md](README.en.md), `docs/en/`).

## Desarrollo

```bash
make check      # formato, vet, tests con -race y validación del feed (lo mismo que el CI)
make build      # ./depsentinel
make dist       # binarios para linux/darwin/windows + SHA256SUMS
```

Estructura, cómo añadir una regla o un ecosistema y el modelo de amenazas: [`docs/arquitectura.md`](docs/arquitectura.md).
Guía de contribución: [`CONTRIBUTING.md`](CONTRIBUTING.md). Seguridad: [`SECURITY.md`](SECURITY.md).

## Antes de publicar

El repositorio usa `AlejandroMolines` como usuario de GitHub de ejemplo. `scripts/set-owner.sh <tu-usuario>` lo sustituye en
todo el proyecto. La lista completa de pasos (claves de firma, GitHub Pages, donaciones) está en
[`docs/hoja-de-ruta.md`](docs/hoja-de-ruta.md).

## Licencia

[MIT](LICENSE). Las donaciones son opcionales y nunca desbloquean funciones: [`docs/transparencia.md`](docs/transparencia.md).
