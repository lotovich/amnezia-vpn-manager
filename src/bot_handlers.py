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
from datetime import datetime, timedelta
from functools import wraps
from typing import Callable, Any

import qrcode
from aiogram import Router, Bot, F
from aiogram.types import (
    Message, BufferedInputFile, 
    ReplyKeyboardMarkup, KeyboardButton,
    InlineKeyboardMarkup, InlineKeyboardButton,
    CallbackQuery
)
from aiogram.filters import Command, CommandStart, StateFilter
from aiogram.enums import ParseMode
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup

from database import Database, Client
from vpn_manager import VPNManager
from stats_viz import (
    generate_traffic_chart, generate_stats_summary,
    generate_series_chart, generate_hourly_chart, generate_weekly_chart,
    format_size
)




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


# States for FSM
class VPNStates(StatesGroup):
    waiting_for_client_name = State()
    waiting_for_app_type = State()
    waiting_for_stats_start = State()
    waiting_for_stats_end = State()


# Main menu keyboard
main_menu = ReplyKeyboardMarkup(
    keyboard=[
        [KeyboardButton(text="👤 Create Client"), KeyboardButton(text="🗑 Delete Client")],
        [KeyboardButton(text="📋 List Clients"), KeyboardButton(text="📊 Statistics")]
    ],
    resize_keyboard=True,
    input_field_placeholder="Select an action"
)


async def full_sync_server() -> None:
    """
    Sync DB clients to config file and reload interface.
    Ensures persistent state matches database state.
    """
    if not _db:
        return
        
    clients = await _db.get_all_clients()
    clients_dicts = [{"public_key": c.public_key, "address": c.address} for c in clients]
    
    # 1. Update config file on disk
    _vpn.update_server_config_file(clients_dicts)
    
    # 2. Sync running interface with new config file
    success = await _vpn.sync_config()
    if success:
        logger.info("Server fully synced with database")
    else:
        logger.error("Failed to sync server configuration")


def setup_handlers(db: Database, vpn: VPNManager) -> Router:
    """Setup handlers with database and VPN manager references."""
    global _db, _vpn
    _db = db
    _vpn = vpn
    return router


@router.message(CommandStart(), StateFilter("*"))
@admin_only
async def cmd_start(message: Message, state: FSMContext) -> None:
    """Handle /start command - show main menu."""
    await state.clear()
    await message.answer(
        "🔐 **AmneziaWG VPN Manager**\n\n"
        "Welcome! Use the menu below to manage your server.\n"
        "All changes are applied synchronously and persisted.",
        reply_markup=main_menu,
        parse_mode=ParseMode.MARKDOWN
    )


@router.message(Command("help"), StateFilter("*"))
@admin_only
async def cmd_help(message: Message) -> None:
    """Handle /help command."""
    await message.answer(
        "📖 **Bot Help**\n\n"
        "• **Create Client**: Request name and get config (QR + file).\n"
        "• **Delete Client**: Show buttons to delete clients.\n"
        "• **Statistics**: Show traffic usage charts.\n"
        "• **List Clients**: Simple text list of all clients.\n\n"
        "All clients are automatically saved to server configuration.",
        reply_markup=main_menu,
        parse_mode=ParseMode.MARKDOWN
    )


@router.message(F.text.contains("Create Client"))
@router.message(Command("create"), StateFilter("*"))
@admin_only
async def start_create_client(message: Message, state: FSMContext) -> None:
    """Start client creation dialog."""
    try:
        # Check if user object exists
        if not message.from_user:
            await message.answer("❌ Error: Cannot identify user.")
            return

        # Set the state - this is the core FSM action
        await state.set_state(VPNStates.waiting_for_client_name)
        
        await message.answer(
            "✍️ **Creating New Client**\n\n"
            "Please enter a name for the new client.\n"
            "Use only letters, numbers, and underscores.",
            reply_markup=main_menu,
            parse_mode=ParseMode.MARKDOWN
        )
        logger.info(f"User {message.from_user.id} started client creation (state set)")
    except Exception as e:
        logger.error(f"start_create_client error: {str(e)}", exc_info=True)
        await message.answer(f"❌ Critical error: `{type(e).__name__}: {str(e)}`")






@router.message(VPNStates.waiting_for_client_name)
@admin_only
async def process_create_client(message: Message, state: FSMContext) -> None:
    """Process client name and ask for app type."""
    client_name = message.text.strip()

    # Validate name
    is_valid, error = validate_client_name(client_name)
    if not is_valid:
        await message.answer(f"❌ {error}\nTry another name:")
        return

    # Check if client already exists
    if await _db.client_exists(client_name):
        await message.answer(f"❌ Client `{client_name}` already exists! Please enter a different name:", parse_mode=ParseMode.MARKDOWN)
        return

    # Store name and ask for app type
    await state.update_data(client_name=client_name)
    await state.set_state(VPNStates.waiting_for_app_type)

    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📱 Amnezia VPN", callback_data="app_type:amnezia_vpn")],
        [InlineKeyboardButton(text="🔐 AmneziaWG", callback_data="app_type:amnezia_wg")]
    ])

    await message.answer(
        f"📱 **Select App Type for `{client_name}`**\n\n"
        "Choose which app you will use to connect. This determines the QR code format:",
        reply_markup=keyboard,
        parse_mode=ParseMode.MARKDOWN
    )


@router.callback_query(F.data.startswith("app_type:"), StateFilter(VPNStates.waiting_for_app_type))
async def process_app_type_callback(callback: CallbackQuery, state: FSMContext):
    """Perform actual client creation based on selected app type."""
    app_type = callback.data.split(":")[1]
    data = await state.get_data()
    client_name = data.get("client_name")
    
    if not client_name:
        await callback.answer("Error: Client name lost. Please try again.", show_alert=True)
        await state.clear()
        return

    try:
        # Mapping app_type to pretty name
        app_name = "Amnezia VPN" if app_type == "amnezia_vpn" else "AmneziaWG"
        
        await callback.message.edit_text(f"⏳ Creating client <b>{client_name}</b> for {app_name}...", parse_mode=ParseMode.HTML)

        # Generate keys and IP
        keypair = await _vpn.generate_keypair()
        client_ip = await _db.get_next_available_ip()

        # Add to database
        await _db.add_client(
            name=client_name,
            public_key=keypair.public_key,
            private_key=keypair.private_key,
            address=client_ip
        )

        # FULL SYNC
        await full_sync_server()

        # Generate client config text
        config_text = _vpn.generate_client_config(
            client_private_key=keypair.private_key,
            client_address=client_ip
        )

        qr_image = None
        qr_data_text = ""

        if app_type == "amnezia_vpn":
            # JSON format
            endpoint = f"{_vpn.vpn_host}:{_vpn.vpn_port}"
            qr_data_base64 = generate_amnezia_qr_data(
                client_private_key=keypair.private_key,
                client_address=client_ip,
                server_public_key=_vpn.server_public_key,
                endpoint=endpoint,
                dns=_vpn.dns,
                awg_params=_vpn.awg_params
            )
            qr_image = generate_qr_code(qr_data_base64)
            qr_data_text = f"vpn://{qr_data_base64}"
        else:
            # AmneziaWG / Standard format: raw config text
            qr_image = generate_qr_code(config_text)
            qr_data_text = config_text

        # Send File
        config_file = BufferedInputFile(config_text.encode(), filename=f"{client_name}.conf")
        await callback.message.answer_document(
            config_file,
            caption=f"✅ Client <b>{client_name}</b> created for <b>{app_name}</b>.\nIP: <code>{client_ip}</code>",
            parse_mode=ParseMode.HTML
        )

        # Send QR Photo
        qr_photo = BufferedInputFile(qr_image, filename=f"{client_name}_qr.png")
        await callback.message.answer_photo(
            qr_photo,
            caption=f"📱 QR code for <b>{app_name}</b>",
            reply_markup=main_menu,
            parse_mode=ParseMode.HTML
        )
        
        # Send Text Key
        if app_type == "amnezia_vpn":
            await callback.message.answer(
                f"🔑 <b>Key for Amnezia VPN</b> (tap to copy):\n\n<code>{qr_data_text}</code>",
                parse_mode=ParseMode.HTML
            )
        else:
            # For AmneziaWG, we use a preformatted block for the INI config
            await callback.message.answer(
                "📝 <b>Config Text</b> (for manual copy):\n\n"
                f"<pre>{qr_data_text}</pre>",
                parse_mode=ParseMode.HTML
            )

        await callback.message.delete()
        logger.info(f"Created client: {client_name} ({client_ip}) for {app_type}")
        await state.clear()
        
    except Exception as e:
        logger.exception(f"Failed to create client: {e}")
        await callback.message.answer(f"❌ Error creating client: {e}", reply_markup=main_menu, parse_mode=None)
        await state.clear()


@router.message(F.text == "🗑 Delete Client", StateFilter("*"))
@router.message(Command("delete"), StateFilter("*"))
@admin_only
async def cmd_delete(message: Message) -> None:
    """Show client deletion menu."""
    clients = await _db.get_all_clients()
    if not clients:
        await message.answer("ℹ️ No clients to delete.")
        return

    # Create inline keyboard with clients
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=f"❌ {c.name}", callback_data=f"del:{c.name}")]
        for c in clients
    ])
    await message.answer("🗑 **Select client to delete:**\nWarning: This action cannot be undone!", reply_markup=keyboard, parse_mode=ParseMode.MARKDOWN)


@router.callback_query(F.data.startswith("del:"))
async def process_delete_callback(callback: CallbackQuery):
    """Handle deletion callback."""
    if not callback.data:
        return
        
    client_name = callback.data.split(":")[1]
    
    # Check existance
    if not await _db.client_exists(client_name):
        await callback.answer("Client already deleted", show_alert=True)
        await callback.message.delete()
        return

    try:
        # Delete from DB
        await _db.delete_client(client_name)
        
        # FULL SYNC (Remove from config and reload interface)
        await full_sync_server()
        
        await callback.answer(f"Client {client_name} deleted")
        await callback.message.edit_text(f"✅ Client `{client_name}` successfully deleted.\nAccess revoked.", parse_mode=ParseMode.MARKDOWN)
        logger.info(f"Deleted client: {client_name}")
        
    except Exception as e:
        logger.exception(f"Delete failed: {e}")
        await callback.answer("Error deleting client", show_alert=True)


@router.message(F.text == "📋 List Clients", StateFilter("*"))
@router.message(Command("list"), StateFilter("*"))
@admin_only
async def cmd_list(message: Message) -> None:
    """List all clients."""
    clients = await _db.get_all_clients()
    
    if not clients:
        await message.answer("ℹ️ No active clients.")
        return

    text = "📋 **Active Clients:**\n\n"
    for c in clients:
        text += f"🔹 `{c.name}` ({c.address})\n"
    
    await message.answer(text, parse_mode=ParseMode.MARKDOWN)


def get_time_ago(timestamp: int) -> str:
    """Format timestamp to relative time string."""
    if not timestamp:
        return "Never"
    
    diff = int(time.time() - timestamp)
    if diff < 0:
        return "Just now"
    if diff < 60:
        return f"{diff} sec. ago"
    elif diff < 3600:
        return f"{diff // 60} min. ago"
    elif diff < 86400:
        return f"{diff // 3600} hours ago"
    else:
        return f"{diff // 86400} days ago"


async def show_stats_root(message: Message, edit: bool = False) -> None:
    """Show root statistics menu (select target)."""
    clients = await _db.get_all_clients()
    
    keyboard_builder = []
    # Button for All Clients
    keyboard_builder.append([InlineKeyboardButton(text="👥 All Clients (Total)", callback_data="stats_sel:ALL")])
    keyboard_builder.append([InlineKeyboardButton(text="🏆 Top Users", callback_data="stats_view:top:ALL")])

    # Buttons for each client (2 per row)
    rows = []
    # Limit number of buttons to avoid Telegram limits
    for c in clients[:50]: 
        rows.append(InlineKeyboardButton(text=f"👤 {c.name}", callback_data=f"stats_sel:{c.name}"))
        if len(rows) == 2:
             keyboard_builder.append(rows)
             rows = []
    if rows:
        keyboard_builder.append(rows)

    keyboard = InlineKeyboardMarkup(inline_keyboard=keyboard_builder)
    text = "📊 **Statistics**\nSelect a client or view global report:"
    
    if edit:
        await message.edit_text(text, reply_markup=keyboard, parse_mode=ParseMode.MARKDOWN)
    else:
        await message.answer(text, reply_markup=keyboard, parse_mode=ParseMode.MARKDOWN)


@router.message(F.text == "📊 Statistics", StateFilter("*"))
@router.message(Command("stats"), StateFilter("*"))
@admin_only
async def cmd_stats(message: Message) -> None:
    """Show traffic statistics menu."""
    await show_stats_root(message)


async def get_client_info_text(client: Client) -> str:
    """Generate detailed formatted text with client statistics."""
    # Get Last Handshake
    last_seen = "Never"
    try:
         stats = await _vpn.get_interface_stats()
         # Find stats for this peer
         peer_stat = next((s for s in stats if s.public_key == client.public_key), None)
         if peer_stat and peer_stat.latest_handshake > 0:
             last_seen = get_time_ago(peer_stat.latest_handshake)
    except Exception as e:
         logger.error(f"Failed to get handshake for {client.name}: {e}")
         
    # Get total traffic
    total_rx, total_tx = await _db.get_client_total_traffic(client.id)
    
    # Get average session duration (all time)
    avg_duration = await _db.get_average_session_duration(client.id)
    avg_session_text = f"{avg_duration:.1f} min" if avg_duration > 0 else "N/A"

    # Get Session Info
    session_text = "None"
    last_session = await _db.get_last_session(client.id)
    if last_session:
        try:
            start_dt = datetime.fromisoformat(last_session["start_at"])
            if last_session["is_active"]:
                duration = datetime.now() - start_dt
                session_text = f"Online for {int(duration.total_seconds() // 60)} min"
            elif last_session.get("end_at"):
                end_dt = datetime.fromisoformat(last_session["end_at"])
                duration = end_dt - start_dt
                session_text = f"Lasted {int(duration.total_seconds() // 60)} min"
            else:
                session_text = "Disconnected"
        except Exception as e:
            logger.error(f"Error parsing session for {client.name}: {e}")
            session_text = "Error"
    
    # Format creation date
    created_at_str = client.created_at.strftime("%Y-%m-%d %H:%M")

    return (
        f"👤 <b>Client</b>: <code>{client.name}</code>\n"
        f"📡 <b>IP</b>: <code>{client.address}</code>\n"
        f"📅 <b>Created At</b>: <code>{created_at_str}</code>\n"
        f"⏱ <b>Last Seen</b>: <code>{last_seen}</code>\n"
        f"⏳ <b>Session</b>: <code>{session_text}</code>\n"
        f"📊 <b>Avg Session</b>: <code>{avg_session_text}</code>\n"
        f"📥 <b>Total Downloaded</b>: <code>{format_size(total_rx)}</code>\n"
        f"📤 <b>Total Uploaded</b>: <code>{format_size(total_tx)}</code>"
    )


@router.callback_query(F.data == "stats_back")
async def process_stats_back(callback: CallbackQuery):
    """Back to root stats menu."""
    await show_stats_root(callback.message, edit=True)


@router.callback_query(F.data.startswith("stats_sel:"))
async def process_stats_selection(callback: CallbackQuery):
    """Handle client selection for stats."""
    target = callback.data.split(":")[1]
    
    if target == "ALL":
        text = "📊 <b>Statistics: Global</b>\nSelect report type:"
    else:
        client = await _db.get_client_by_name(target)
        if not client:
             await callback.answer("Client not found", show_alert=True)
             return
             
        # Get formatted info text
        info_text = await get_client_info_text(client)
        text = f"📊 <b>Statistics: {client.name}</b>\n\n{info_text}\n\nSelect report type:"

    # Menu for selected target
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="⌚ Last Hour", callback_data=f"stats_view:60m:{target}")],
        [InlineKeyboardButton(text="📈 Dynamics (24h)", callback_data=f"stats_view:24h:{target}"),
         InlineKeyboardButton(text="📈 Dynamics (7d)", callback_data=f"stats_view:7d:{target}")],
        [InlineKeyboardButton(text="📅 Custom Range...", callback_data=f"stats_view:custom:{target}")],
        [InlineKeyboardButton(text="🕒 Hourly Profile", callback_data=f"stats_view:daily:{target}"),
         InlineKeyboardButton(text="🗓 Weekly Profile", callback_data=f"stats_view:weekly:{target}")],
        [InlineKeyboardButton(text="🔙 Back", callback_data="stats_back")]
    ])
    
    await callback.message.edit_text(text, reply_markup=keyboard, parse_mode=ParseMode.HTML)


@router.callback_query(F.data.startswith("stats_view:"))
async def process_stats_view(callback: CallbackQuery, state: FSMContext):
    """Generate and show specific chart."""
    _, action, target = callback.data.split(":")
    
    # Check for Custom Range Action first
    if action == "custom":
        await state.set_state(VPNStates.waiting_for_stats_start)
        await state.update_data(target_client=target)
        await callback.message.answer(
            "📅 <b>Custom Date Range</b>\n\n"
            "Please enter the <b>Start Date</b> (YYYY-MM-DD).\n"
            "Example: <code>2024-01-01</code>",
            parse_mode=ParseMode.HTML
        )
        await callback.answer()
        return

    # Normal charts
    client_id = None
    target_name = "Global"
    info_text = ""

    if target != "ALL":
        client = await _db.get_client_by_name(target)
        if client:
            client_id = client.id
            target_name = client.name
            info_text = "\n\n" + await get_client_info_text(client)

    try:
        await callback.message.edit_text("⏳ Generating chart...")
        
        # Determine time range for average session duration
        avg_session = 0.0
        if client_id:
            if action == "60m":
                avg_session = await _db.get_average_session_duration(client_id, minutes=60)
            elif action == "24h":
                avg_session = await _db.get_average_session_duration(client_id, days=1)
            elif action == "7d":
                avg_session = await _db.get_average_session_duration(client_id, days=7)
            # custom, daily, weekly can be added if needed, but these are the main ones
        
        avg_text = ""
        if avg_session > 0:
            avg_text = f"\n⏱ <b>Avg Session Duration</b>: <code>{avg_session:.1f} min</code>"

        if action == "60m":
            data = await _db.get_minute_traffic_series(client_id=client_id, minutes=60)
            chart_img = generate_series_chart(data, f"Last Hour Activity: {target_name}")
            caption = f"⌚ <b>Last Hour Activity</b>: {target_name}{info_text}{avg_text}"
            
        elif action == "24h":
            data = await _db.get_traffic_series(days=1, client_id=client_id)
            chart_img = generate_series_chart(data, f"Traffic History (24h): {target_name}")
            caption = f"📈 <b>Dynamics (24h)</b>: {target_name}{info_text}{avg_text}"
            
        elif action == "7d":
            data = await _db.get_traffic_series(days=7, client_id=client_id)
            chart_img = generate_series_chart(data, f"Traffic History (7d): {target_name}")
            caption = f"📈 <b>Dynamics (7d)</b>: {target_name}{info_text}{avg_text}"
            
        elif action == "daily":
            data = await _db.get_hourly_activity(client_id=client_id)
            chart_img = generate_hourly_chart(data, f"Hourly Activity Profile: {target_name}")
            caption = f"🕒 <b>Hourly Profile</b>: {target_name}{info_text}"
            
        elif action == "weekly":
            data = await _db.get_weekly_activity(client_id=client_id)
            chart_img = generate_weekly_chart(data, f"Weekly Activity Profile: {target_name}")
            caption = f"🗓 <b>Weekly Profile</b>: {target_name}{info_text}"
            
        elif action == "top":
            traffic_data = await _db.get_total_traffic_by_client()
            chart_img = generate_traffic_chart(traffic_data, "Top Users by Total Traffic")
            caption = "🏆 <b>Top Users by Total Traffic</b>"
            
        else:
            await callback.answer("Action not supported yet", show_alert=True)
            return

        if chart_img:
            file = BufferedInputFile(chart_img, filename="chart.png")
            await callback.message.answer_photo(
                file, 
                caption=caption,
                parse_mode=ParseMode.HTML,
                reply_markup=main_menu
            )
            await callback.message.delete()
        else:
            await callback.message.edit_text(f"📊 No data for <b>{target_name}</b> in this period.", parse_mode=ParseMode.HTML)
            
    except Exception as e:
        logger.exception(f"Stats generation failed: {e}")
        try:
            await callback.message.edit_text(f"❌ Error: {e}")
        except:
             pass
    
    await callback.answer()


@router.message(VPNStates.waiting_for_stats_start)
async def process_stats_start_date(message: Message, state: FSMContext) -> None:
    """Handle start date input."""
    date_str = message.text.strip()
    try:
        datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        await message.answer("❌ Invalid format! Please use YYYY-MM-DD (e.g., 2024-01-01).")
        return
        
    await state.update_data(start_date=date_str)
    await state.set_state(VPNStates.waiting_for_stats_end)
    await message.answer(
        "📅 **End Date**\n\n"
        "Please enter the **End Date** (YYYY-MM-DD).\n"
        "Send `today` to use current date.",
        parse_mode=ParseMode.MARKDOWN
    )


@router.message(VPNStates.waiting_for_stats_end)
async def process_stats_end_date(message: Message, state: FSMContext) -> None:
    """Handle end date input and generate chart."""
    date_str = message.text.strip().lower()
    data = await state.get_data()
    start_date = data["start_date"]
    
    if date_str == "today":
        end_date = datetime.now().strftime("%Y-%m-%d")
    else:
        try:
            datetime.strptime(date_str, "%Y-%m-%d")
            end_date = date_str
        except ValueError:
            await message.answer("❌ Invalid format! Please use YYYY-MM-DD or 'today'.")
            return
            
    if start_date > end_date:
        await message.answer("❌ Start date cannot be after end date!")
        return
        
    # Generate Chart
    await message.answer("⏳ Generating chart...")
    
    try:
        target = data["target_client"]
        target_name = "All Clients"
        client_id = None
        
        if target != "ALL":
             client = await _db.get_client_by_name(target)
             if client:
                 client_id = client.id
                 target_name = client.name
                 
        traffic_data = await _db.get_traffic_series_range(start_date, end_date, client_id)
        
        chart_img = generate_series_chart(traffic_data, f"Traffic: {start_date} to {end_date}\n{target_name}")
        
        if chart_img:
             file = BufferedInputFile(chart_img, filename="custom_stats.png")
             await message.answer_photo(
                 file, 
                 caption=f"📈 **Custom Range Report**\nPeriod: `{start_date}` - `{end_date}`\nTarget: `{target_name}`",
                 parse_mode=ParseMode.MARKDOWN
             )
        else:
             await message.answer("❌ No data found for this period.")
             
    except Exception as e:
        logger.exception(f"Custom stats error: {e}")
        await message.answer(f"❌ Error: {e}")
    finally:
        await state.clear()



@router.message(F.text, StateFilter("*"))
@admin_only
async def unknown_command(message: Message) -> None:
    """Handle unknown messages."""
    logger.warning(f"Unknown command from user {message.from_user.id}: {message.text}")
    # Use HTML to avoid issues with special characters in user text
    safe_text = message.text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    await message.answer(
        f"❓ Unknown command: <code>{safe_text}</code>\n\nPlease use the menu below:",
        reply_markup=main_menu,
        parse_mode=ParseMode.HTML
    )

