SHELL := /bin/bash
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
PKG     := github.com/AlejandroMolines/depsentinel/internal/version
LDFLAGS := -s -w -buildid= -X $(PKG).Version=$(VERSION) -X $(PKG).Commit=$(COMMIT) -X $(PKG).Date=$(DATE)
TARGETS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

.PHONY: help build install test race vet fmt check run dogfood docker dist db-keygen db-check db-sign db-verify clean

help: ## Muestra esta ayuda
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'

build: ## Compila ./depsentinel
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o depsentinel ./cmd/depsentinel

install: ## Instala el binario en $GOBIN
	CGO_ENABLED=0 go install -trimpath -ldflags "$(LDFLAGS)" ./cmd/depsentinel

test: ## Ejecuta los tests
	go test -count=1 ./...

race: ## Ejecuta los tests con el detector de carreras
	go test -race -count=1 ./...

vet: ## go vet
	go vet ./...

fmt: ## Comprueba el formato (falla si hay ficheros sin formatear)
	@test -z "$$(gofmt -l .)" || { echo "Ficheros sin formatear:"; gofmt -l .; exit 1; }

check: fmt vet race db-check ## Todo lo que exige el CI
	bash -n action/entrypoint.sh

run: build ## Escanea este mismo repositorio sin conexión
	./depsentinel scan . --offline

dogfood: build ## Escanea el repositorio y falla con riesgo alto
	./depsentinel scan . --ci --fail-on high

docker: ## Construye la imagen depsentinel/depsentinel
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE) -t depsentinel/depsentinel:$(VERSION) .

dist: ## Binarios para todas las plataformas + SHA256SUMS (en dist/)
	rm -rf dist && mkdir -p dist
	@for t in $(TARGETS); do \
	  os=$${t%/*}; arch=$${t#*/}; ext=""; [ "$$os" = windows ] && ext=".exe"; \
	  name="depsentinel_$(VERSION)_$${os}_$${arch}"; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o "dist/$${name}$${ext}" ./cmd/depsentinel || exit 1; \
	done
	cd dist && sha256sum * > SHA256SUMS && cat SHA256SUMS

db-keygen: ## Genera la clave de firma del feed (una sola vez)
	go run ./cmd/dbtool keygen

db-check: ## Valida db/malicious.json y db/popular.json
	go run ./cmd/dbtool check -dir db

db-sign: ## Regenera db/index.json y su firma (usa DB_SIGNING_KEY o KEY=fichero)
	go run ./cmd/dbtool sign -dir db $(if $(KEY),-key $(KEY),)

db-verify: ## Verifica la firma del feed publicado en db/
	go run ./cmd/dbtool verify -dir db

clean: ## Borra binarios y artefactos
	rm -rf depsentinel dbtool dist coverage.out
