FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X securevault/pkg/server.Version=${VERSION}" -o securevault ./cmd/server

FROM alpine:3.19

RUN apk add --no-cache ca-certificates curl jq

RUN adduser -D -u 1000 vault
RUN mkdir -p /vault/data /vault/config /vault/audit && chown -R vault:vault /vault

COPY --from=builder /build/securevault /usr/local/bin/securevault

USER vault
WORKDIR /vault

EXPOSE 8200 8201

# Alive when it answers, sealed or not: a sealed or uninitialized vault is
# still running and waiting for an operator (see /v1/sys/health)
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD curl -sf -o /dev/null 'http://localhost:8200/v1/sys/health?standbyok=true&uninitcode=204&sealedcode=204' || exit 1

ENTRYPOINT ["securevault"]
CMD ["-config", "/vault/config/config.yaml"]
