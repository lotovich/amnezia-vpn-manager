"""
Telegram bot handlers for VPN management.
"""

import base64
import io
import json
import logging
import os
import re
import struct
import time
import zlib
from functools import wraps
from typing import Callable, Any

import qrcode
from aiogram import Router, Bot, F
from aiogram.types import Message, BufferedInputFile
from aiogram.filters import Command, CommandStart
from aiogram.enums import ParseMode

from database import Database
from vpn_manager import VPNManager
from stats_viz import generate_traffic_chart, generate_stats_summary

logger = logging.getLogger(__name__)
router = Router()

# Rate limiting: track last command time per user
_last_command_time: dict[int, float] = {}
RATE_LIMIT_SECONDS = 1.0


def get_admin_ids() -> set[int]:
    """Get admin IDs from environment variable."""
    admin_ids_str = os.getenv("ADMIN_IDS", "")
    if not admin_ids_str:
        logger.warning("ADMIN_IDS not set, bot will not respond to anyone!")
        return set()

    ids = set()
    for id_str in admin_ids_str.split(","):
        id_str = id_str.strip()
        if id_str.isdigit():
            ids.add(int(id_str))
    return ids


def admin_only(func: Callable) -> Callable:
    """Decorator to restrict command to admin users only."""
    @wraps(func)
    async def wrapper(message: Message, *args, **kwargs) -> Any:
        user_id = message.from_user.id
        admin_ids = get_admin_ids()

        # Check whitelist
        if user_id not in admin_ids:
            logger.warning(f"Unauthorized access attempt from user {user_id}")
            return  # Silent ignore for security

        # Rate limiting
        current_time = time.time()
        last_time = _last_command_time.get(user_id, 0)
        if current_time - last_time < RATE_LIMIT_SECONDS:
            logger.warning(f"Rate limit hit for user {user_id}")
            await message.answer("⏳ Too fast! Please wait a moment.")
            return

        _last_command_time[user_id] = current_time

        # Log command
        logger.info(f"Command from admin {user_id}: {message.text}")

        return await func(message, *args, **kwargs)

    return wrapper


def validate_client_name(name: str) -> tuple[bool, str]:
    """
    Validate client name.
    Returns (is_valid, error_message).
    """
    if not name:
        return False, "Client name cannot be empty"

    if len(name) > 32:
        return False, "Client name too long (max 32 characters)"

    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        return False, "Client name can only contain letters, numbers, underscores and hyphens"

    return True, ""


def generate_qr_code(data: str) -> bytes:
    """Generate QR code image from data string.
    
    Uses larger box_size and higher error correction for better
    camera scanning, especially on phone screens.
    """
    qr = qrcode.QRCode(
        version=None,  # Auto-size based on data
        error_correction=qrcode.constants.ERROR_CORRECT_M,  # Medium for better scanning
        box_size=15,  # Larger boxes for much better scanning
        border=6,     # Wider border for easier detection
    )
    qr.add_data(data)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return buf.getvalue()


def generate_amnezia_qr_data(
    client_private_key: str,
    client_address: str,
    server_public_key: str,
    endpoint: str,
    dns: str,
    awg_params: dict
) -> str:
    """
    Generate AmneziaVPN-compatible QR code data.
    Format: vpn://base64(json)
    """
    host = endpoint.split(":")[0]
    port = int(endpoint.split(":")[1]) if ":" in endpoint else 51820

    # Build the WireGuard config string with AWG parameters
    wg_config = f"""[Interface]
Address = {client_address}
DNS = {dns}
PrivateKey = {client_private_key}
Jc = {awg_params.get("Jc", 4)}
Jmin = {awg_params.get("Jmin", 40)}
Jmax = {awg_params.get("Jmax", 70)}
S1 = {awg_params.get("S1", 0)}
S2 = {awg_params.get("S2", 0)}
H1 = {awg_params.get("H1", 1)}
H2 = {awg_params.get("H2", 2)}
H3 = {awg_params.get("H3", 3)}
H4 = {awg_params.get("H4", 4)}

[Peer]
PublicKey = {server_public_key}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {endpoint}
PersistentKeepalive = 25"""

    # Build last_config JSON string (nested config)
    # This must be a JSON string containing the full config and fields
    last_config_data = {
        "H1": str(awg_params.get("H1", 1)),
        "H2": str(awg_params.get("H2", 2)),
        "H3": str(awg_params.get("H3", 3)),
        "H4": str(awg_params.get("H4", 4)),
        "Jc": str(awg_params.get("Jc", 4)),
        "Jmax": str(awg_params.get("Jmax", 70)),
        "Jmin": str(awg_params.get("Jmin", 40)),
        "S1": str(awg_params.get("S1", 0)),
        "S2": str(awg_params.get("S2", 0)),
        "allowed_ips": ["0.0.0.0/0", "::/0"],
        "client_ip": client_address.split('/')[0],
        "client_priv_key": client_private_key,
        "config": wg_config,  # The INI config goes here
        "hostName": host,
        "mtu": "1280",
        "persistent_keep_alive": "25",
        "port": port,
        "server_pub_key": server_public_key,
        "transport_proto": "udp"
    }
    last_config_str = json.dumps(last_config_data)

    # AmneziaVPN main JSON structure
    config = {
        "containers": [
            {
                "awg": {
                    "H1": str(awg_params.get("H1", 1)),
                    "H2": str(awg_params.get("H2", 2)),
                    "H3": str(awg_params.get("H3", 3)),
                    "H4": str(awg_params.get("H4", 4)),
                    "Jc": str(awg_params.get("Jc", 4)),
                    "Jmax": str(awg_params.get("Jmax", 70)),
                    "Jmin": str(awg_params.get("Jmin", 40)),
                    "S1": str(awg_params.get("S1", 0)),
                    "S2": str(awg_params.get("S2", 0)),
                    "last_config": last_config_str,
                    "port": str(port),
                    "transport_proto": "udp"
                },
                "container": "amnezia-awg"
            }
        ],
        "defaultContainer": "amnezia-awg",
        "description": "Amne Server",
        "dns1": dns,
        "dns2": "",
        "hostName": host
    }

    # Encode using AmneziaVPN format (12-byte header):
    # 1. JSON
    # 2. Compress with zlib
    # 3. Header: Magic(4) + TotalRemaining(4) + UncompressedLen(4)
    # Magic = 0x07c00100
    
    json_str = json.dumps(config)  # Compact JSON
    json_bytes = json_str.encode('utf-8')
    uncompressed_len = len(json_bytes)

    # Compress
    compressed = zlib.compress(json_bytes)
    
    # Header format:
    # Magic Bytes: 07 c0 01 00
    # Total Remaining Length (4 bytes) = 4 bytes (UncompressedLen field) + len(compressed)
    # Uncompressed Length (4 bytes)
    magic = b'\x07\xc0\x01\x00'
    total_remaining_len = 4 + len(compressed)
    
    header = magic + struct.pack('>I', total_remaining_len) + struct.pack('>I', uncompressed_len)
    data_with_header = header + compressed

    # URL-safe base64 (no padding)
    b64_data = base64.urlsafe_b64encode(data_with_header).decode().rstrip('=')

    # Return raw Base64 for QR code (no prefix)
    return b64_data


# Store references to shared objects (set from main.py)
_db: Database = None
_vpn: VPNManager = None


def setup_handlers(db: Database, vpn: VPNManager) -> Router:
    """Setup handlers with database and VPN manager references."""
    global _db, _vpn
    _db = db
    _vpn = vpn
    return router


@router.message(CommandStart())
@admin_only
async def cmd_start(message: Message) -> None:
    """Handle /start command."""
    await message.answer(
        "🔐 **AmneziaWG VPN Manager**\n\n"
        "Available commands:\n"
        "• `/create <name>` — Create new VPN client\n"
        "• `/delete <name>` — Delete VPN client\n"
        "• `/list` — List all clients\n"
        "• `/stats` — Show traffic statistics\n"
        "• `/help` — Show this message",
        parse_mode=ParseMode.MARKDOWN
    )


@router.message(Command("help"))
@admin_only
async def cmd_help(message: Message) -> None:
    """Handle /help command."""
    await cmd_start(message)


@router.message(Command("create"))
@admin_only
async def cmd_create(message: Message) -> None:
    """
    Handle /create <client_name> command.
    Creates a new VPN client with generated keys.
    """
    # Parse client name from command
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        await message.answer(
            "❌ Usage: `/create <client_name>`\n"
            "Example: `/create phone_john`",
            parse_mode=ParseMode.MARKDOWN
        )
        return

    client_name = parts[1].strip()

    # Validate name
    is_valid, error = validate_client_name(client_name)
    if not is_valid:
        await message.answer(f"❌ {error}")
        return

    # Check if client already exists
    if await _db.client_exists(client_name):
        await message.answer(f"❌ Client `{client_name}` already exists!", parse_mode=ParseMode.MARKDOWN)
        return

    try:
        # Send "working" message
        status_msg = await message.answer("⏳ Generating keys...")

        # Generate keys
        keypair = await _vpn.generate_keypair()

        # Get next available IP
        client_ip = await _db.get_next_available_ip()

        # Add to database
        client = await _db.add_client(
            name=client_name,
            public_key=keypair.public_key,
            private_key=keypair.private_key,
            address=client_ip
        )

        # Add peer to running interface
        await _vpn.add_peer(keypair.public_key, client_ip)

        # Generate client config
        config = _vpn.generate_client_config(
            client_private_key=keypair.private_key,
            client_address=client_ip
        )

        # Generate AmneziaVPN-compatible QR code data (Raw Base64)
        endpoint = f"{_vpn.vpn_host}:{_vpn.vpn_port}"
        qr_data_base64 = generate_amnezia_qr_data(
            client_private_key=keypair.private_key,
            client_address=client_ip,
            server_public_key=_vpn.server_public_key,
            endpoint=endpoint,
            dns=_vpn.dns,
            awg_params=_vpn.awg_params
        )

        # Generate QR code image from Raw Base64 (Amnezia format)
        qr_image = generate_qr_code(qr_data_base64)
        
        # Delete status message
        await status_msg.delete()

        # Send config file (Native .conf)
        config_file = BufferedInputFile(
            config.encode(),
            filename=f"{client_name}.conf"
        )
        await message.answer_document(
            config_file,
            caption=f"✅ Client `{client_name}` created!\nIP: `{client_ip}`",
            parse_mode=ParseMode.MARKDOWN
        )

        # Send QR code as photo (Raw Base64 data)
        qr_photo = BufferedInputFile(qr_image, filename=f"{client_name}_qr.png")
        await message.answer_photo(
            qr_photo,
            caption="📱 Scan with AmneziaVPN app"
        )
        
        # Send text key with vpn:// prefix (copy-paste)
        vpn_link = f"vpn://{qr_data_base64}"
        await message.answer(
            f"🔑 **For AmneziaVPN app** (tap to copy):\n\n"
            f"`{vpn_link}`",
            parse_mode=ParseMode.MARKDOWN
        )

        logger.info(f"Created client: {client_name} with IP {client_ip}")

    except Exception as e:
        logger.exception(f"Failed to create client: {e}")
        await message.answer(f"❌ Failed to create client: {e}")


@router.message(Command("delete"))
@admin_only
async def cmd_delete(message: Message) -> None:
    """Handle /delete <client_name> command."""
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        await message.answer(
            "❌ Usage: `/delete <client_name>`",
            parse_mode=ParseMode.MARKDOWN
        )
        return

    client_name = parts[1].strip()

    # Get client info before deletion
    client = await _db.get_client_by_name(client_name)
    if not client:
        await message.answer(f"❌ Client `{client_name}` not found!", parse_mode=ParseMode.MARKDOWN)
        return

    try:
        # Remove from running interface
        await _vpn.remove_peer(client.public_key)

        # Remove from database
        await _db.delete_client(client_name)

        await message.answer(f"✅ Client `{client_name}` deleted!", parse_mode=ParseMode.MARKDOWN)
        logger.info(f"Deleted client: {client_name}")

    except Exception as e:
        logger.exception(f"Failed to delete client: {e}")
        await message.answer(f"❌ Failed to delete client: {e}")


@router.message(Command("list"))
@admin_only
async def cmd_list(message: Message) -> None:
    """Handle /list command - show all clients."""
    clients = await _db.get_all_clients()

    if not clients:
        await message.answer("📋 No clients configured yet.")
        return

    lines = ["📋 **VPN Clients:**\n"]
    for i, client in enumerate(clients, 1):
        created = client.created_at.strftime("%Y-%m-%d")
        lines.append(f"{i}. `{client.name}` — {client.address} (created {created})")

    await message.answer("\n".join(lines), parse_mode=ParseMode.MARKDOWN)


@router.message(Command("stats"))
@admin_only
async def cmd_stats(message: Message) -> None:
    """Handle /stats command - show traffic statistics with chart."""
    try:
        # Get traffic data from database
        traffic_data = await _db.get_total_traffic_by_client()

        if not traffic_data:
            await message.answer("📊 No traffic data collected yet.")
            return

        # Generate chart
        chart_image = generate_traffic_chart(traffic_data)

        # Generate text summary
        summary = generate_stats_summary(traffic_data)

        if chart_image:
            # Send chart with summary as caption
            chart_file = BufferedInputFile(chart_image, filename="traffic_stats.png")
            await message.answer_photo(chart_file, caption=summary, parse_mode=ParseMode.MARKDOWN)
        else:
            # Just send text if chart generation failed
            await message.answer(summary, parse_mode=ParseMode.MARKDOWN)

    except Exception as e:
        logger.exception(f"Failed to generate stats: {e}")
        await message.answer(f"❌ Failed to generate stats: {e}")


@router.message(F.text)
@admin_only
async def unknown_command(message: Message) -> None:
    """Handle unknown text messages."""
    if message.text.startswith("/"):
        await message.answer(
            "❓ Unknown command. Use /help to see available commands."
        )
