#!/bin/bash
set -e

CONFIG_FILE="/etc/amneziawg/awg0.conf"
INTERFACE="awg0"

# Colors for logging
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Validate required environment variables
if [ -z "$BOT_TOKEN" ]; then
    log_error "BOT_TOKEN is not set!"
    exit 1
fi

if [ -z "$ADMIN_IDS" ]; then
    log_error "ADMIN_IDS is not set!"
    exit 1
fi

if [ -z "$SERVER_PRIVATE_KEY" ]; then
    log_error "SERVER_PRIVATE_KEY is not set!"
    log_error "Generate keys with: docker run --rm amnezia-vpn awg genkey | tee privatekey | awg pubkey > publickey"
    exit 1
fi

if [ -z "$VPN_HOST" ]; then
    log_error "VPN_HOST is not set!"
    exit 1
fi

# Set defaults
VPN_PORT=${VPN_PORT:-51820}
VPN_DNS=${VPN_DNS:-1.1.1.1}

# AWG obfuscation parameters (defaults based on working server)
AWG_Jc=${AWG_Jc:-2}
AWG_Jmin=${AWG_Jmin:-10}
AWG_Jmax=${AWG_Jmax:-50}
AWG_S1=${AWG_S1:-107}
AWG_S2=${AWG_S2:-28}
AWG_H1=${AWG_H1:-1359490391}
AWG_H2=${AWG_H2:-1285506284}
AWG_H3=${AWG_H3:-1393261750}
AWG_H4=${AWG_H4:-432419882}

log_info "Starting AmneziaWG VPN Manager..."
log_info "VPN Host: $VPN_HOST"
log_info "VPN Port: $VPN_PORT"

# Function to update config parameter
update_param() {
    local param=$1
    local value=$2
    local file=$3
    
    if grep -q "^$param =" "$file"; then
        sed -i "s|^$param = .*|$param = $value|" "$file"
    else
        # If parameter missing, add it to Interface section (simplistic approach, assumes Interface is at top)
        # Better: use proper INI parser or just append if safe, but sed replace is safer for existing params
        # For simplicity, we warn if missing, as initial config should have had them
        log_warn "Parameter $param not found in config, could not update."
    fi
}

# Create initial server config if not exists
if [ ! -f "$CONFIG_FILE" ]; then
    log_info "Creating initial server configuration..."

    cat > "$CONFIG_FILE" << EOF
[Interface]
PrivateKey = ${SERVER_PRIVATE_KEY}
Address = 10.8.0.1/24
ListenPort = ${VPN_PORT}
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
Jc = ${AWG_Jc}
Jmin = ${AWG_Jmin}
Jmax = ${AWG_Jmax}
S1 = ${AWG_S1}
S2 = ${AWG_S2}
H1 = ${AWG_H1}
H2 = ${AWG_H2}
H3 = ${AWG_H3}
H4 = ${AWG_H4}
EOF

    chmod 600 "$CONFIG_FILE"
    log_info "Server configuration created at $CONFIG_FILE"
else
    log_info "Updating existing server configuration with new parameters..."
    # Force update parameters to match current defaults/env vars
    # This ensures "broken" config gets fixed on restart
    update_param "Jc" "${AWG_Jc}" "$CONFIG_FILE"
    update_param "Jmin" "${AWG_Jmin}" "$CONFIG_FILE"
    update_param "Jmax" "${AWG_Jmax}" "$CONFIG_FILE"
    update_param "S1" "${AWG_S1}" "$CONFIG_FILE"
    update_param "S2" "${AWG_S2}" "$CONFIG_FILE"
    update_param "H1" "${AWG_H1}" "$CONFIG_FILE"
    update_param "H2" "${AWG_H2}" "$CONFIG_FILE"
    update_param "H3" "${AWG_H3}" "$CONFIG_FILE"
    update_param "H4" "${AWG_H4}" "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"
    log_info "Server configuration parameters updated."
fi

# Ensure TUN device exists
if [ ! -c /dev/net/tun ]; then
    log_info "Creating TUN device..."
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200
    chmod 600 /dev/net/tun
fi

# Function to start VPN interface
start_vpn() {
    log_info "Starting AmneziaWG interface..."

    # Start amneziawg-go in background (userspace implementation)
    amneziawg-go $INTERFACE &
    AWG_PID=$!

    # Wait a moment for interface to be created
    sleep 2

    # Configure the interface
    awg setconf $INTERFACE <(awg-quick strip "$CONFIG_FILE")

    # Set IP address
    ip addr add 10.8.0.1/24 dev $INTERFACE 2>/dev/null || true
    ip link set $INTERFACE up

    # Setup NAT (iptables)
    iptables -A FORWARD -i $INTERFACE -j ACCEPT 2>/dev/null || true
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || true

    log_info "AmneziaWG interface $INTERFACE is up"
}

# Function to stop VPN interface
stop_vpn() {
    log_warn "Stopping AmneziaWG interface..."
    ip link set $INTERFACE down 2>/dev/null || true
    ip link delete $INTERFACE 2>/dev/null || true
    killall amneziawg-go 2>/dev/null || true
}

# Cleanup on exit
cleanup() {
    log_warn "Received shutdown signal..."
    stop_vpn
    exit 0
}

trap cleanup SIGTERM SIGINT

# Start VPN
start_vpn

# Start Python bot
log_info "Starting Telegram bot..."
cd /app
exec python main.py
