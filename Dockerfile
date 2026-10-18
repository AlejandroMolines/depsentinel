# syntax=docker/dockerfile:1
# Imagen mínima y sin root: `docker run --rm -v $(pwd):/src depsentinel/depsentinel scan /src`
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -buildid= \
      -X github.com/AlejandroMolines/depsentinel/internal/version.Version=${VERSION} \
      -X github.com/AlejandroMolines/depsentinel/internal/version.Commit=${COMMIT} \
      -X github.com/AlejandroMolines/depsentinel/internal/version.Date=${DATE}" \
    -o /out/depsentinel ./cmd/depsentinel

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/depsentinel /usr/local/bin/depsentinel
ENV DEPSENTINEL_CACHE_DIR=/tmp/depsentinel-cache
USER 65532:65532
WORKDIR /src
ENTRYPOINT ["/usr/local/bin/depsentinel"]
CMD ["--help"]
