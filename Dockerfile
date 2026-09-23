# AmneziaWG VPN Manager - All-in-One Container
# Based on Debian with amneziawg-go (userspace implementation)

FROM golang:1.25-bookworm AS awg-builder

# Let Go fetch a newer toolchain if upstream go.mod requires it
ENV GOTOOLCHAIN=auto

# Build amneziawg-go from source
WORKDIR /build
RUN git clone https://github.com/amnezia-vpn/amneziawg-go.git && \
    cd amneziawg-go && \
    make && \
    cp amneziawg-go /usr/local/bin/amneziawg-go

# Build amneziawg-tools
RUN git clone https://github.com/amnezia-vpn/amneziawg-tools.git && \
    cd amneziawg-tools/src && \
    make && \
    cp wg /usr/local/bin/awg && \
    cp wg-quick/linux.bash /usr/local/bin/awg-quick


# Final image
FROM python:3.11-slim-bookworm

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    iproute2 \
    procps \
    openresolv \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Xray-core (cascade mode: transparent proxy from awg0 to the exit server).
# Pinned to the same release as the exit server; the zip bundles geoip/geosite.
ARG XRAY_VERSION=v26.3.27
RUN curl -fsSL -o /tmp/xray.zip \
        "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-64.zip" \
    && mkdir -p /tmp/xray /usr/local/share/xray \
    && unzip -q /tmp/xray.zip -d /tmp/xray \
    && install -m 755 /tmp/xray/xray /usr/local/bin/xray \
    && install -m 644 /tmp/xray/geoip.dat /tmp/xray/geosite.dat /usr/local/share/xray/ \
    && rm -rf /tmp/xray /tmp/xray.zip \
    && xray version | head -1
ENV XRAY_LOCATION_ASSET=/usr/local/share/xray

# Copy amneziawg binaries from builder
COPY --from=awg-builder /usr/local/bin/amneziawg-go /usr/local/bin/
COPY --from=awg-builder /usr/local/bin/awg /usr/local/bin/
COPY --from=awg-builder /usr/local/bin/awg-quick /usr/local/bin/

# Make awg-quick executable
RUN chmod +x /usr/local/bin/awg-quick

# Create directories
RUN mkdir -p /etc/amneziawg /data /app

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY src/ ./

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose VPN port (UDP)
EXPOSE 51820/udp

# Volume for persistent data
VOLUME ["/data", "/etc/amneziawg"]

ENTRYPOINT ["/entrypoint.sh"]
