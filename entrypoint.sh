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


# ---------------------------------------------------------------------------
# Cascade mode: this server is the entry node; non-Russian traffic from awg0 is
# transparently proxied (TPROXY) into Xray and sent to the exit server over
# VLESS + XHTTP + TLS. Everything else keeps working as in single-server mode.
# ---------------------------------------------------------------------------
CASCADE_ENABLED=${CASCADE_ENABLED:-0}
XRAY_CONFIG="/etc/xray/config.json"
XRAY_TPROXY_PORT=12345
XRAY_SOCKS_TEST_PORT=1081

write_xray_config() {
    mkdir -p /etc/xray
    python3 - "$XRAY_CONFIG" <<'PY'
import json, os, sys

def env(name, default=""):
    return os.environ.get(name, default).strip()

exit_host = env("EXIT_HOST")
exit_port = int(env("EXIT_PORT", "443"))
exit_sni  = env("EXIT_SNI") or exit_host
exit_uuid = env("EXIT_UUID")
exit_path = env("EXIT_PATH", "/")
ru_direct  = env("CASCADE_RU_DIRECT", "1") == "1"
block_quic = env("CASCADE_BLOCK_QUIC", "1") == "1"
tproxy_port = int(env("XRAY_TPROXY_PORT", "12345"))
socks_port  = int(env("XRAY_SOCKS_TEST_PORT", "1081"))

missing = [k for k, v in (("EXIT_HOST", exit_host), ("EXIT_UUID", exit_uuid)) if not v]
if missing:
    sys.exit("cascade: missing " + ", ".join(missing))

sniff = {"enabled": True, "destOverride": ["http", "tls", "quic"]}
rules = [
    # Client DNS (any resolver) -> Xray built-in DoH resolver, over the tunnel
    {"type": "field", "inboundTag": ["tproxy-in", "socks-test"], "port": 53, "outboundTag": "dns-out"},
    {"type": "field", "ip": ["geoip:private"], "outboundTag": "block"},
]
if block_quic:
    rules.append({"type": "field", "network": "udp", "port": 443, "outboundTag": "block"})
if ru_direct:
    rules.append({"type": "field", "domain": ["geosite:category-ru"], "outboundTag": "direct"})
    rules.append({"type": "field", "ip": ["geoip:ru"], "outboundTag": "direct"})
rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "proxy"})

cfg = {
    "log": {"loglevel": "warning"},
    "dns": {"servers": ["https://1.1.1.1/dns-query"], "queryStrategy": "UseIPv4"},
    "inbounds": [
        {
            "tag": "tproxy-in",
            "listen": "0.0.0.0",
            "port": tproxy_port,
            "protocol": "dokodemo-door",
            "settings": {"network": "tcp,udp", "followRedirect": True},
            "sniffing": sniff,
            "streamSettings": {"sockopt": {"tproxy": "tproxy"}},
        },
        {
            "tag": "socks-test",
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"udp": True},
            "sniffing": sniff,
        },
    ],
    "outbounds": [
        {
            "tag": "proxy",
            "protocol": "vless",
            "settings": {"vnext": [{"address": exit_host, "port": exit_port,
                                    "users": [{"id": exit_uuid, "encryption": "none"}]}]},
            "streamSettings": {
                "network": "xhttp",
                "security": "tls",
                "tlsSettings": {"serverName": exit_sni, "alpn": ["h2", "http/1.1"]},
                "xhttpSettings": {"host": exit_sni, "path": exit_path, "mode": "packet-up"},
            },
        },
        {"tag": "direct", "protocol": "freedom",
         "streamSettings": {"sockopt": {"domainStrategy": "UseIPv4"}}},
        {"tag": "block", "protocol": "blackhole"},
        {"tag": "dns-out", "protocol": "dns"},
    ],
    "routing": {"domainStrategy": "IPIfNonMatch", "rules": rules},
}
with open(sys.argv[1], "w") as f:
    json.dump(cfg, f, indent=2)
PY
    chmod 600 "$XRAY_CONFIG"
}

# TPROXY rules: only packets arriving from awg0, destined outside private ranges.
# Xray's own outbound traffic leaves via eth0 and never re-enters awg0, so no
# mark-based loop guard is needed (see Xray docs, level-2/tproxy).
setup_tproxy() {
    # Reverse-path check must not use the TPROXY mark, otherwise the lookup
    # lands in table 100 (local default) and packets are dropped as martians.
    for f in /proc/sys/net/ipv4/conf/all/src_valid_mark /proc/sys/net/ipv4/conf/$INTERFACE/src_valid_mark; do
        [ -w "$f" ] && echo 0 > "$f" || log_warn "cannot write $f (set net.ipv4.conf.all.src_valid_mark=0 via compose sysctls)"
    done
    ip rule add fwmark 1 table 100 2>/dev/null || true
    ip route add local default dev lo table 100 2>/dev/null || true

    iptables -t mangle -N XRAY 2>/dev/null || iptables -t mangle -F XRAY
    for net in 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 \
               192.0.0.0/24 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4 255.255.255.255/32; do
        iptables -t mangle -A XRAY -d "$net" -j RETURN
    done
    iptables -t mangle -A XRAY -p tcp -j TPROXY --on-port "$XRAY_TPROXY_PORT" --tproxy-mark 1
    iptables -t mangle -A XRAY -p udp -j TPROXY --on-port "$XRAY_TPROXY_PORT" --tproxy-mark 1
    iptables -t mangle -C PREROUTING -i "$INTERFACE" -j XRAY 2>/dev/null || \
        iptables -t mangle -A PREROUTING -i "$INTERFACE" -j XRAY
}

teardown_tproxy() {
    iptables -t mangle -D PREROUTING -i "$INTERFACE" -j XRAY 2>/dev/null || true
    iptables -t mangle -F XRAY 2>/dev/null || true
    iptables -t mangle -X XRAY 2>/dev/null || true
    ip rule del fwmark 1 table 100 2>/dev/null || true
    ip route del local default dev lo table 100 2>/dev/null || true
}

start_cascade() {
    log_info "Cascade mode: exit ${EXIT_HOST}:${EXIT_PORT:-443} (RU direct=${CASCADE_RU_DIRECT:-1}, block QUIC=${CASCADE_BLOCK_QUIC:-1})"
    write_xray_config || { log_error "Cascade config failed"; return 1; }
    if ! xray run -test -config "$XRAY_CONFIG" >/dev/null 2>&1; then
        log_error "Xray config is invalid:"; xray run -test -config "$XRAY_CONFIG" 2>&1 | tail -3
        return 1
    fi
    setup_tproxy
    # Supervised: if Xray dies, TPROXY would redirect into a dead port and every
    # non-RU connection would hang, so restart it until the container stops.
    (
        while true; do
            xray run -config "$XRAY_CONFIG"
            echo "[WARN] Xray exited (code $?), restarting in 2s" >&2
            sleep 2
        done
    ) &
    XRAY_PID=$!
    sleep 1
    if pgrep -x xray >/dev/null; then
        log_info "Xray started (supervisor pid $XRAY_PID), TPROXY on port $XRAY_TPROXY_PORT, SOCKS on 127.0.0.1:$XRAY_SOCKS_TEST_PORT"
    else
        log_error "Xray failed to start"; kill "$XRAY_PID" 2>/dev/null; teardown_tproxy; return 1
    fi
}

stop_cascade() {
    [ "$CASCADE_ENABLED" = "1" ] || return 0
    log_warn "Stopping cascade..."
    teardown_tproxy
    [ -n "$XRAY_PID" ] && kill "$XRAY_PID" 2>/dev/null || true
    pkill -x xray 2>/dev/null || true
}

# Cleanup on exit
cleanup() {
    log_warn "Received shutdown signal..."
    stop_cascade
    stop_vpn
    exit 0
}

trap cleanup SIGTERM SIGINT

# Start VPN
start_vpn

# Start cascade (optional)
if [ "$CASCADE_ENABLED" = "1" ]; then
    start_cascade || log_error "Cascade disabled due to errors; traffic will exit directly from this server"
fi

# Start Python bot
log_info "Starting Telegram bot..."
cd /app
exec python main.py
