#!/usr/bin/env bash
# Sustituye el usuario de GitHub de ejemplo ("tuusuario") por el tuyo en todo el repositorio:
# módulo de Go, imports, workflows, landing, panel, documentación y feed.
#
#   scripts/set-owner.sh mi-usuario
#
# Después ejecuta `go build ./... && go test ./...` y haz commit.
set -euo pipefail

owner="${1:-}"
if [[ -z "$owner" || ! "$owner" =~ ^[A-Za-z0-9][A-Za-z0-9-]*$ ]]; then
  echo "uso: $0 <usuario-de-github>" >&2
  exit 2
fi

cd "$(dirname "$0")/.."
files="$(grep -rIl 'tuusuario' . --exclude-dir=.git --exclude-dir=dist --exclude=set-owner.sh || true)"
if [[ -z "$files" ]]; then
  echo "No queda ninguna referencia a «tuusuario»."
  exit 0
fi
while IFS= read -r f; do
  sed -i.bak "s/tuusuario/${owner}/g" "$f" && rm -f "$f.bak"
done <<< "$files"
echo "Actualizados $(wc -l <<< "$files" | tr -d ' ') ficheros. Revisa con: git diff --stat"
echo "Recuerda también: la imagen de Docker (depsentinel/depsentinel) y los enlaces de donación (Open Collective, Ko-fi)."
