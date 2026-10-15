# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/bw-serve ./cmd/bw-serve && \
    mkdir -p /out/data

FROM gcr.io/distroless/static-debian13:nonroot

# Vault Management API port (same as `bw serve`)
EXPOSE 8087/tcp

ENV BW_HOST=https://vault.bitwarden.com \
    BITWARDENCLI_APPDATA_DIR=/data \
    VAULT_SYNC_INTERVAL=120

COPY --from=build /out/bw-serve /usr/local/bin/bw-serve
COPY --from=build --chown=65532:65532 /out/data /data

USER 65532:65532

HEALTHCHECK --start-period=15s --start-interval=2s --interval=10s --timeout=3s --retries=3 \
    CMD ["/usr/local/bin/bw-serve", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/bw-serve"]
