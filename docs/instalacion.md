**Español** | [English](en/installation.md)

# Instalación

## Con Go (recomendado)

```bash
go install github.com/AlejandroMolines/depsentinel/cmd/depsentinel@latest
depsentinel version
```

Requiere Go 1.22 o superior. El binario queda en `$(go env GOPATH)/bin`; asegúrate de que está en tu `PATH`.
Para una versión concreta: `...@v1.0.0`.

## Con Docker

```bash
docker run --rm -v $(pwd):/src depsentinel/depsentinel scan /src
```

La imagen es mínima (`distroless`) y se ejecuta sin root. Si quieres escribir informes en el directorio montado,
ejecuta con tu usuario: `docker run --rm --user $(id -u):$(id -g) -v $(pwd):/src depsentinel/depsentinel scan /src -o /src/report.json --format json`.

## Binarios de las releases

Cada release publica binarios para Linux, macOS y Windows (amd64 y arm64 salvo Windows), un fichero `SHA256SUMS` y una
atestación de procedencia firmada por GitHub.

```bash
# 1) comprueba la suma
sha256sum --check --ignore-missing SHA256SUMS

# 2) comprueba la procedencia (quién y cómo lo compiló)
gh attestation verify depsentinel_v1.0.0_linux_amd64 --owner AlejandroMolines
```

## Desde el código fuente

```bash
git clone https://github.com/AlejandroMolines/depsentinel && cd depsentinel
make build          # ./depsentinel
make install        # en $GOBIN
```

## Actualizar la base de datos

DepSentinel funciona sin descargar nada (OSV en cada escaneo + semilla embebida). Para el feed ampliado:

```bash
depsentinel db update      # verifica la firma Ed25519 antes de usarlo
depsentinel db status      # muestra versión, antigüedad y fuente
```

Si quieres mantenerla al día, prográmala. Con cron (cada día a las 6:00):

```cron
0 6 * * * /usr/local/bin/depsentinel db update >/dev/null 2>&1
```

En CI, la Action admite `update-db: "true"` cuando el feed y su clave pública están configurados.

## Dónde guarda cosas

* Caché (avisos de OSV, metadatos de registries, feed): el directorio de caché del usuario
  (`~/.cache/depsentinel` en Linux). Cámbialo con `DEPSENTINEL_CACHE_DIR`. Se limpia con `depsentinel db clean`.
* Configuración y lista blanca: dentro del proyecto (`.depsentinel.json`, `.depsentinel/allowlist.json`).

## Desinstalar

Borra el binario y el directorio de caché. DepSentinel no instala servicios ni deja procesos.
