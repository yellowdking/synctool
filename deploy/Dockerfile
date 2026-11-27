# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
ARG COMMIT=none

WORKDIR /src
COPY go.mod ./
COPY internal/ ./internal/
COPY cmd/synctool-relay/ ./cmd/synctool-relay/

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -o /out/synctool-relay ./cmd/synctool-relay

# Prepare empty writable mountpoint owned by non-root UID/GID 65532 for scratch runtime.
RUN mkdir -p /data && chown 65532:65532 /data

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/synctool-relay /synctool-relay
COPY --from=builder --chown=65532:65532 /data /data

USER 65532:65532
EXPOSE 54843

ENV SYNCTOOL_LISTEN=:54843 \
    SYNCTOOL_PROFILE=auto \
    SYNCTOOL_SPOOL=auto \
    SYNCTOOL_TLS=selfsigned \
    SYNCTOOL_DATA_DIR=/data

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/synctool-relay", "healthcheck"]

ENTRYPOINT ["/synctool-relay"]
CMD ["serve"]
