# Build Stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git make build-base

# Copy go mod/sum
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build Proxy
RUN go build -o /bin/ads-httpproxy ./cmd/proxy

# Build Admin Tool
RUN go build -o /bin/ads-admin ./cmd/ads-admin

# Build Migration Tool
RUN go build -o /bin/squid2ads ./cmd/squid2ads

# Final Stage
FROM alpine:3.19

WORKDIR /app

# Install runtime dependencies (ca-certificates for HTTPS, tzdata)
RUN apk add --no-cache ca-certificates tzdata

# Copy binaries
COPY --from=builder /bin/ads-httpproxy /usr/local/bin/
COPY --from=builder /bin/ads-admin /usr/local/bin/
COPY --from=builder /bin/squid2ads /usr/local/bin/

# Create non-root user
RUN adduser -D -g '' proxyuser
USER proxyuser

# Expose ports
# 8080: HTTP Proxy
# 1080: SOCKS5 Proxy
# 9090: Admin API
# 9091: gRPC API
# 443/udp: HTTP/3 (QUIC)
EXPOSE 8080 1080 9090 9091 443/udp

# Default Config
ENV ADS_ADDR=:8080
ENV ADS_SOCKS_ADDR=:1080
ENV ADS_API_ADDR=:9090
ENV ADS_ENABLE_QUIC=true

ENTRYPOINT ["/usr/local/bin/ads-httpproxy"]
