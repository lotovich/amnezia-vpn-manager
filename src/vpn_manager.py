"""
VPN Manager module for AmneziaWG.
Handles key generation, config creation, and interface management.
"""

import asyncio
import os
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# AmneziaWG obfuscation parameters
# These are defaults that can be overridden via environment variables
DEFAULT_AWG_PARAMS = {
    "Jc": 2,            # Junk packet count (reduced from 4)
    "Jmin": 10,         # Junk packet minimum size (reduced from 40)
    "Jmax": 50,         # Junk packet maximum size (reduced from 70)
    "S1": 107,          # Init packet junk size
    "S2": 28,           # Response packet junk size
    "H1": 1359490391,   # Init packet magic header (random high value)
    "H2": 1285506284,   # Response packet magic header (random high value)
    "H3": 1393261750,   # Cookie packet magic header (random high value)
    "H4": 432419882,    # Transport packet magic header (random high value)
}


def get_awg_params() -> dict[str, int]:
    """Get AWG obfuscation parameters from env or defaults."""
    params = {}
    for key, default in DEFAULT_AWG_PARAMS.items():
        env_value = os.getenv(f"AWG_{key}")
        if env_value is not None:
            try:
                params[key] = int(env_value)
            except ValueError:
                logger.warning(f"Invalid value for AWG_{key}: {env_value}, using default")
                params[key] = default
        else:
            params[key] = default
    return params


@dataclass
class KeyPair:
    """WireGuard key pair."""
    private_key: str
    public_key: str


@dataclass
class TrafficStats:
    """Traffic statistics for a peer."""
    public_key: str
    endpoint: Optional[str]
    allowed_ips: str
    latest_handshake: int  # Unix timestamp
    bytes_received: int
    bytes_sent: int


class VPNManager:
    """Manages AmneziaWG VPN operations."""

    def __init__(
        self,
        interface: str = "awg0",
        server_private_key: Optional[str] = None,
        server_public_key: Optional[str] = None,
        vpn_host: Optional[str] = None,
        vpn_port: int = 51820,
        dns: str = "1.1.1.1",
    ):
        self.interface = interface
        self.server_private_key = server_private_key or os.getenv("SERVER_PRIVATE_KEY", "")
        self.server_public_key = server_public_key or os.getenv("SERVER_PUBLIC_KEY", "")
        self.vpn_host = vpn_host or os.getenv("VPN_HOST", "vpn.example.com")
        self.vpn_port = vpn_port
        self.dns = dns
        self.awg_params = get_awg_params()

    async def _run_command(self, *args: str) -> tuple[str, str, int]:
        """Run a shell command and return stdout, stderr, returncode."""
        logger.debug(f"Running command: {' '.join(args)}")
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        return stdout.decode().strip(), stderr.decode().strip(), proc.returncode

    async def generate_keypair(self) -> KeyPair:
        """Generate a new WireGuard key pair using awg."""
        # Generate private key
        stdout, stderr, code = await self._run_command("awg", "genkey")
        if code != 0:
            raise RuntimeError(f"Failed to generate private key: {stderr}")
        private_key = stdout

        # Derive public key
        proc = await asyncio.create_subprocess_exec(
            "awg", "pubkey",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout_bytes, stderr_bytes = await proc.communicate(private_key.encode())
        if proc.returncode != 0:
            raise RuntimeError(f"Failed to derive public key: {stderr_bytes.decode()}")
        public_key = stdout_bytes.decode().strip()

        return KeyPair(private_key=private_key, public_key=public_key)

    def generate_client_config(
        self,
        client_private_key: str,
        client_address: str,
    ) -> str:
        """Generate client configuration file content."""
        params = self.awg_params
        config = f"""[Interface]
PrivateKey = {client_private_key}
Address = {client_address}
DNS = {self.dns}
Jc = {params['Jc']}
Jmin = {params['Jmin']}
Jmax = {params['Jmax']}
S1 = {params['S1']}
S2 = {params['S2']}
H1 = {params['H1']}
H2 = {params['H2']}
H3 = {params['H3']}
H4 = {params['H4']}

[Peer]
PublicKey = {self.server_public_key}
Endpoint = {self.vpn_host}:{self.vpn_port}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""
        return config

    def generate_server_config(self, clients: list[dict]) -> str:
        """
        Generate server configuration file content.
        clients: list of dicts with 'public_key' and 'address' keys
        """
        params = self.awg_params
        config = f"""[Interface]
PrivateKey = {self.server_private_key}
Address = 10.8.0.1/24
ListenPort = {self.vpn_port}
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
Jc = {params['Jc']}
Jmin = {params['Jmin']}
Jmax = {params['Jmax']}
S1 = {params['S1']}
S2 = {params['S2']}
H1 = {params['H1']}
H2 = {params['H2']}
H3 = {params['H3']}
H4 = {params['H4']}
"""
        for client in clients:
            config += f"""
[Peer]
PublicKey = {client['public_key']}
AllowedIPs = {client['address']}
"""
        return config

    async def add_peer(self, public_key: str, allowed_ips: str) -> bool:
        """Add a peer to the running interface (hot-add, no restart)."""
        # Use awg set to add peer on-the-fly
        _, stderr, code = await self._run_command(
            "awg", "set", self.interface,
            "peer", public_key,
            "allowed-ips", allowed_ips
        )
        if code != 0:
            logger.error(f"Failed to add peer: {stderr}")
            return False

        logger.info(f"Added peer {public_key[:16]}... with IP {allowed_ips}")
        return True

    async def remove_peer(self, public_key: str) -> bool:
        """Remove a peer from the running interface."""
        _, stderr, code = await self._run_command(
            "awg", "set", self.interface,
            "peer", public_key,
            "remove"
        )
        if code != 0:
            logger.error(f"Failed to remove peer: {stderr}")
            return False

        logger.info(f"Removed peer {public_key[:16]}...")
        return True

    async def get_interface_stats(self) -> list[TrafficStats]:
        """
        Get traffic statistics for all peers.
        Parses output of 'awg show <interface> dump'.
        """
        stdout, stderr, code = await self._run_command(
            "awg", "show", self.interface, "dump"
        )
        if code != 0:
            logger.error(f"Failed to get stats: {stderr}")
            return []

        stats = []
        lines = stdout.split("\n")

        # First line is interface info, skip it
        # Format: private_key public_key listen_port fwmark
        # Peer lines: public_key preshared_key endpoint allowed_ips latest_handshake rx tx

        for line in lines[1:]:  # Skip first line (interface info)
            if not line.strip():
                continue

            parts = line.split("\t")
            if len(parts) >= 7:
                public_key = parts[0]
                # preshared_key = parts[1]  # Usually "(none)"
                endpoint = parts[2] if parts[2] != "(none)" else None
                allowed_ips = parts[3]
                latest_handshake = int(parts[4]) if parts[4] != "0" else 0
                bytes_received = int(parts[5])
                bytes_sent = int(parts[6])

                stats.append(TrafficStats(
                    public_key=public_key,
                    endpoint=endpoint,
                    allowed_ips=allowed_ips,
                    latest_handshake=latest_handshake,
                    bytes_received=bytes_received,
                    bytes_sent=bytes_sent,
                ))

        return stats

    async def is_interface_up(self) -> bool:
        """Check if the VPN interface is up."""
        _, _, code = await self._run_command("awg", "show", self.interface)
        return code == 0

    async def sync_config(self, config_path: str = "/etc/amneziawg/awg0.conf") -> bool:
        """
        Sync configuration file with running interface.
        This applies changes without dropping existing connections.
        """
        # Use awg-quick strip to get the config, then awg syncconf
        stdout, stderr, code = await self._run_command(
            "awg-quick", "strip", config_path
        )
        if code != 0:
            logger.error(f"Failed to strip config: {stderr}")
            return False

        # Write stripped config to temp file
        temp_config = "/tmp/awg_stripped.conf"
        with open(temp_config, "w") as f:
            f.write(stdout)

        # Sync with running interface
        _, stderr, code = await self._run_command(
            "awg", "syncconf", self.interface, temp_config
        )
        if code != 0:
            logger.error(f"Failed to sync config: {stderr}")
            return False

        return True


def format_bytes(bytes_count: int) -> str:
    """Format bytes to human-readable string."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_count < 1024:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024
    return f"{bytes_count:.2f} PB"
