FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o securevault ./cmd/server

FROM alpine:3.19

RUN apk add --no-cache ca-certificates curl jq

RUN adduser -D -u 1000 vault
RUN mkdir -p /vault/data /vault/config /vault/audit && chown -R vault:vault /vault

COPY --from=builder /build/securevault /usr/local/bin/securevault

USER vault
WORKDIR /vault

EXPOSE 8200 8201

# Health check accepts any HTTP response (sealed vault returns 503 but is still running)
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD curl -s -o /dev/null -w '%{http_code}' http://localhost:8200/v1/health | grep -qE '(200|503)' || exit 1

ENTRYPOINT ["securevault"]
CMD ["-config", "/vault/config/config.yaml"]
