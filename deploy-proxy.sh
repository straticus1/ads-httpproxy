#!/bin/bash
# Deploy ads-httpproxy to apps2 server

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SCRIPT_DIR/ads-httpproxy-linux"
SERVER="apps2"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${GREEN}[deploy]${NC} $1"; }
warn() { echo -e "${YELLOW}[warn]${NC} $1"; }
error() { echo -e "${RED}[error]${NC} $1"; exit 1; }

# Check binary exists
[ -f "$BINARY" ] || error "Binary not found: $BINARY"

log "Deploying ads-httpproxy to $SERVER..."
log "Binary: $BINARY ($(ls -lh $BINARY | awk '{print $5}'))"
echo ""

# Create directory structure
log "Creating directory structure..."
ssh "$SERVER" "mkdir -p /opt/ads-httpproxy/{bin,config,logs,plugins,scripts}"

# Upload binary
log "Uploading binary..."
scp "$BINARY" "$SERVER:/opt/ads-httpproxy/bin/ads-httpproxy"
ssh "$SERVER" "chmod +x /opt/ads-httpproxy/bin/ads-httpproxy"

# Upload example config if doesn't exist
if ! ssh "$SERVER" "test -f /opt/ads-httpproxy/config/config.yaml"; then
    log "Creating default config..."
    cat > /tmp/proxy-config.yaml << 'EOF'
addr: ":8080"
api_addr: ":9090"
api_secret: "CHANGE_ME_$(openssl rand -hex 16)"

bandwidth_limit: 10485760  # 10 MB/s

# Redis (optional, for caching and clustering)
redis:
  enabled: false
  addr: "localhost:6379"
  password: ""
  db: 0

# HTTP Response Caching
cache:
  enabled: true
  memory:
    enabled: true
    max_size_mb: 500
    max_ttl: 60
  default_ttl: 3600
  max_ttl: 86400

# Logging
logging:
  level: info
  file: /opt/ads-httpproxy/logs/proxy.log

# Authentication (optional)
# auth:
#   mechanism: "basic"
#   users:
#     - username: "admin"
#       password: "changeme"

# URL Reputation (optional)
reputation:
  enabled: false
EOF
    scp /tmp/proxy-config.yaml "$SERVER:/opt/ads-httpproxy/config/config.yaml"
    rm /tmp/proxy-config.yaml
    warn "⚠ Update /opt/ads-httpproxy/config/config.yaml with your settings!"
fi

# Upload example configs from repo
if [ -d "$SCRIPT_DIR/examples" ]; then
    log "Uploading example configs..."
    scp -r "$SCRIPT_DIR/examples" "$SERVER:/opt/ads-httpproxy/"
fi

# Create systemd service
log "Creating systemd service..."
ssh "$SERVER" "cat > /etc/systemd/system/ads-httpproxy.service" << 'EOF'
[Unit]
Description=ADS HTTP Proxy Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/ads-httpproxy
ExecStart=/opt/ads-httpproxy/bin/ads-httpproxy -config /opt/ads-httpproxy/config/config.yaml
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and enable service
ssh "$SERVER" "systemctl daemon-reload"
ssh "$SERVER" "systemctl enable ads-httpproxy"

log "✓ Deployed to $SERVER"
echo ""
log "Next steps:"
log "1. Edit config: ssh $SERVER 'vi /opt/ads-httpproxy/config/config.yaml'"
log "2. Generate API secret: openssl rand -hex 32"
log "3. Start service: ssh $SERVER 'systemctl start ads-httpproxy'"
log "4. Check status: ssh $SERVER 'systemctl status ads-httpproxy'"
log "5. View logs: ssh $SERVER 'journalctl -u ads-httpproxy -f'"
log "6. Test proxy: curl -x http://<server-ip>:8080 http://example.com"
log "7. API stats: curl -H \"X-API-Key: YOUR_KEY\" http://<server-ip>:9090/stats"
log "8. Cache stats: curl -H \"X-API-Key: YOUR_KEY\" http://<server-ip>:9090/api/cache/stats"
