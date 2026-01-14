#!/bin/bash
set -e

REPO="HyBuild-net/quic-relay"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/quic-relay"
SYSTEMD_DIR="/etc/systemd/system"
SERVICE_FILE="quic-relay.service"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Please run as root (sudo $0)"
        exit 1
    fi
}

check_systemd() {
    if ! command -v systemctl &> /dev/null; then
        log_error "systemd is required but not found"
        exit 1
    fi
}

detect_arch() {
    local arch
    arch=$(uname -m)
    case $arch in
        x86_64)  echo "amd64" ;;
        aarch64) echo "arm64" ;;
        arm64)   echo "arm64" ;;
        *)
            log_error "Unsupported architecture: $arch"
            exit 1
            ;;
    esac
}

create_user() {
    if ! id "quic-relay" &>/dev/null; then
        log_info "Creating quic-relay user..."
        useradd --system --no-create-home --shell /usr/sbin/nologin quic-relay
    else
        log_info "User quic-relay already exists"
    fi
}

download_binary() {
    local arch="$1"
    local binary_name="quic-relay-linux-${arch}"
    local url="https://github.com/${REPO}/releases/latest/download/${binary_name}"

    log_info "Downloading quic-relay for ${arch}..."

    if command -v curl &> /dev/null; then
        curl -fsSL -o "${INSTALL_DIR}/quic-relay" "$url"
    elif command -v wget &> /dev/null; then
        wget -qO "${INSTALL_DIR}/quic-relay" "$url"
    else
        log_error "curl or wget is required"
        exit 1
    fi

    chmod +x "${INSTALL_DIR}/quic-relay"
    log_info "Binary installed to ${INSTALL_DIR}/quic-relay"
}

install_config() {
    mkdir -p "$CONFIG_DIR"

    if [ -f "${CONFIG_DIR}/config.json" ]; then
        log_warn "Config already exists at ${CONFIG_DIR}/config.json, skipping"
    else
        log_info "Creating default config..."
        cat > "${CONFIG_DIR}/config.json" << 'EOF'
{
  "listen": ":5520",
  "handlers": [
    {"type": "ratelimit-global", "config": {"max_parallel_connections": 10000}},
    {"type": "logsni"},
    {
      "type": "sni-router",
      "config": {
        "routes": {
          "play.example.com": "127.0.0.1:5521",
          "lobby.example.com": "127.0.0.1:5522"
        }
      }
    },
    {"type": "forwarder"}
  ]
}
EOF
        chown quic-relay:quic-relay "${CONFIG_DIR}/config.json"
        chmod 640 "${CONFIG_DIR}/config.json"
    fi
}

install_service() {
    local service_url="https://raw.githubusercontent.com/${REPO}/master/dist/${SERVICE_FILE}"

    log_info "Installing systemd service..."

    if command -v curl &> /dev/null; then
        curl -fsSL -o "${SYSTEMD_DIR}/${SERVICE_FILE}" "$service_url"
    elif command -v wget &> /dev/null; then
        wget -qO "${SYSTEMD_DIR}/${SERVICE_FILE}" "$service_url"
    fi

    chmod 644 "${SYSTEMD_DIR}/${SERVICE_FILE}"
    systemctl daemon-reload
}

enable_service() {
    log_info "Enabling quic-relay service..."
    systemctl enable quic-relay
}

restart_if_running() {
    if systemctl is-active --quiet quic-relay; then
        log_info "Restarting quic-relay service..."
        systemctl restart quic-relay
    fi
}

main() {
    echo ""
    echo "  QUIC Relay Installer"
    echo "  ====================="
    echo ""

    check_root
    check_systemd

    local arch
    arch=$(detect_arch)
    log_info "Detected architecture: ${arch}"

    create_user
    download_binary "$arch"
    install_config
    install_service
    enable_service
    restart_if_running

    echo ""
    log_info "Installation complete!"
    echo ""
    echo "  Next steps:"
    echo "    1. Edit config:  nano ${CONFIG_DIR}/config.json"
    echo "    2. Start:        systemctl start quic-relay"
    echo "    3. Check status: systemctl status quic-relay"
    echo "    4. View logs:    journalctl -u quic-relay -f"
    echo ""
}

main "$@"
