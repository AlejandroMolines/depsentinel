#!/usr/bin/env bash
# Entrada de la GitHub Action de DepSentinel.
# - Compila el binario desde el mismo commit que la acción (si se usa desde este repositorio)
#   o lo instala con `go install` (si la acción vive en otro repositorio).
# - Ejecuta el escaneo una sola vez y genera JSON, Markdown (comentario de PR) y HTML.
# - Comenta en el PR (si procede) y deja el código de salida en un output para que la acción
#   pueda subir el informe antes de fallar.
set -uo pipefail

ACTION_PATH="${ACTION_PATH:?falta ACTION_PATH}"
OUT_DIR="${RUNNER_TEMP:-/tmp}/depsentinel"
mkdir -p "$OUT_DIR"
BIN="$OUT_DIR/depsentinel"

out() { [ -n "${GITHUB_OUTPUT:-}" ] && echo "$1=$2" >> "$GITHUB_OUTPUT"; return 0; }

# json_get FICHERO EXPRESIÓN_JQ DEFECTO: usa jq si existe y, si no, python3 (los runners de GitHub traen ambos).
json_get() {
  local file="$1" expr="$2" default="$3" value=""
  if command -v jq >/dev/null 2>&1; then
    value="$(jq -r "$expr // empty" "$file" 2>/dev/null)"
  elif command -v python3 >/dev/null 2>&1; then
    value="$(python3 - "$file" "$expr" <<'PY' 2>/dev/null
import json, sys
data = json.load(open(sys.argv[1]))
cur = data
for part in sys.argv[2].lstrip('.').split('.'):
    if part:
        cur = cur.get(part) if isinstance(cur, dict) else None
print("" if cur is None else cur)
PY
)"
  fi
  [ -n "$value" ] && echo "$value" || echo "$default"
}

# 1) Binario
if [ -f "$ACTION_PATH/../go.mod" ] && [ -d "$ACTION_PATH/../cmd/depsentinel" ]; then
  if ! (cd "$ACTION_PATH/.." && go build -trimpath -o "$BIN" ./cmd/depsentinel); then
    echo "::error title=DepSentinel::No se pudo compilar DepSentinel desde el repositorio de la acción."
    out exit-code 3
    exit 0
  fi
else
  if ! GOBIN="$OUT_DIR" go install "github.com/AlejandroMolines/depsentinel/cmd/depsentinel@${INPUT_VERSION:-latest}"; then
    echo "::error title=DepSentinel::No se pudo instalar DepSentinel (versión ${INPUT_VERSION:-latest})."
    out exit-code 3
    exit 0
  fi
fi

# 2) Base de datos (opcional)
if [ "${INPUT_UPDATE_DB:-false}" = "true" ]; then
  "$BIN" db update || echo "::warning title=DepSentinel::No se pudo actualizar la base de datos; se usa la semilla o el último feed descargado."
fi

# 3) Escaneo
args=(scan "${INPUT_PATH:-.}" --ci --fail-on "${INPUT_FAIL_ON:-high}" --ecosystem "${INPUT_ECOSYSTEM:-auto}"
      --format json --output "$OUT_DIR/report.json"
      --output-markdown "$OUT_DIR/comment.md" --output-html "$OUT_DIR/report.html")
[ "${INPUT_DEEP:-false}" = "true" ] && args+=(--deep)
if [ -n "${INPUT_EXTRA_ARGS:-}" ]; then
  read -r -a extra <<< "$INPUT_EXTRA_ARGS"
  args+=("${extra[@]}")
fi
"$BIN" "${args[@]}"
code=$?

out exit-code "$code"
out report-dir "$OUT_DIR"
out report-path "$OUT_DIR/report.json"
if [ -f "$OUT_DIR/report.json" ]; then
  out risk-level "$(json_get "$OUT_DIR/report.json" '.summary.risk_level' low)"
  out findings "$(json_get "$OUT_DIR/report.json" '.summary.findings' 0)"
fi

# 4) Resumen del job
if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ -f "$OUT_DIR/comment.md" ]; then
  cat "$OUT_DIR/comment.md" >> "$GITHUB_STEP_SUMMARY"
fi

# 5) Comentario en el pull request (se actualiza el anterior en lugar de duplicarlo)
if [ "${INPUT_COMMENT_ON_PR:-true}" = "true" ] && [ -f "$OUT_DIR/comment.md" ] && [ -n "${GITHUB_EVENT_PATH:-}" ] \
   && command -v gh >/dev/null 2>&1; then
  pr="$(json_get "$GITHUB_EVENT_PATH" '.pull_request.number' '')"
  if [ -n "$pr" ]; then
    marker='<!-- depsentinel-report -->'
    existing="$(gh api "repos/${GITHUB_REPOSITORY}/issues/${pr}/comments" --paginate \
      --jq ".[] | select(.body | contains(\"${marker}\")) | .id" 2>/dev/null | head -n1)"
    if [ -n "$existing" ]; then
      gh api -X PATCH "repos/${GITHUB_REPOSITORY}/issues/comments/${existing}" -F body=@"$OUT_DIR/comment.md" >/dev/null \
        || echo "::warning title=DepSentinel::No se pudo actualizar el comentario del PR (¿token de solo lectura en un fork?)."
    else
      gh api -X POST "repos/${GITHUB_REPOSITORY}/issues/${pr}/comments" -F body=@"$OUT_DIR/comment.md" >/dev/null \
        || echo "::warning title=DepSentinel::No se pudo publicar el comentario del PR (¿token de solo lectura en un fork?)."
    fi
  fi
fi

exit 0
