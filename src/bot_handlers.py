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

from database import Database
from vpn_manager import VPNManager
from stats_viz import (
    generate_traffic_chart, generate_stats_summary,
    generate_series_chart, generate_hourly_chart, generate_weekly_chart
)


class VPNStates(StatesGroup):
    """FSM states for interactive dialogs."""
    waiting_for_client_name = State()


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



# Main menu keyboard
main_menu = ReplyKeyboardMarkup(
    keyboard=[
        [KeyboardButton(text="👤 Создать клиента"), KeyboardButton(text="🗑 Удалить клиента")],
        [KeyboardButton(text="📊 Статистика"), KeyboardButton(text="📋 Список клиентов")],
        [KeyboardButton(text="🆘 Помощь")]
    ],
    resize_keyboard=True,
    input_field_placeholder="Выберите действие"
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


@router.message(CommandStart())
@admin_only
async def cmd_start(message: Message, state: FSMContext) -> None:
    """Handle /start command - show main menu."""
    await state.clear()
    await message.answer(
        "🔐 **AmneziaWG VPN Manager**\n\n"
        "Добро пожаловать! Используйте меню для управления сервером.\n"
        "Все изменения применяются синхронно и сохраняются.",
        reply_markup=main_menu,
        parse_mode=ParseMode.MARKDOWN
    )


@router.message(Command("help"))
@router.message(F.text == "🆘 Помощь")
@admin_only
async def cmd_help(message: Message) -> None:
    """Handle /help command."""
    await message.answer(
        "📖 **Справка по боту**\n\n"
        "• **Создать клиента**: Запросит имя и выдаст конфиг (QR + файл).\n"
        "• **Удалить клиента**: Покажет список кнопок для удаления.\n"
        "• **Статистика**: Показывает графики использования трафика.\n"
        "• **Список**: Простой текстовый список всех клиентов.\n\n"
        "Все клиенты автоматически сохраняются в конфигурации сервера.",
        reply_markup=main_menu,
        parse_mode=ParseMode.MARKDOWN
    )

@router.message(F.text == "👤 Создать клиента")
@admin_only
async def start_create_client(message: Message, state: FSMContext) -> None:
    """Start client creation dialog."""
    await message.answer("✍️ Введите имя для нового клиента (латиница, цифры, _):", reply_markup=main_menu)
    await state.set_state(VPNStates.waiting_for_client_name)


@router.message(VPNStates.waiting_for_client_name)
@admin_only
async def process_create_client(message: Message, state: FSMContext) -> None:
    """Process client name and create VPN config."""
    client_name = message.text.strip()

    # Validate name
    is_valid, error = validate_client_name(client_name)
    if not is_valid:
        await message.answer(f"❌ {error}\nПопробуйте другое имя:")
        return

    # Check if client already exists
    if await _db.client_exists(client_name):
        await message.answer(f"❌ Клиент `{client_name}` уже существует! Введите другое имя:", parse_mode=ParseMode.MARKDOWN)
        return

    try:
        status_msg = await message.answer("⏳ Создание клиента и синхронизация сервера...")

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

        # FULL SYNC: Update server config file and allow interface to reload
        # This ensures persistence and "real" update
        await full_sync_server()

        # Generate client config (for user)
        config = _vpn.generate_client_config(
            client_private_key=keypair.private_key,
            client_address=client_ip
        )

        # Generate AmneziaVPN QR data (Raw Base64)
        endpoint = f"{_vpn.vpn_host}:{_vpn.vpn_port}"
        qr_data_base64 = generate_amnezia_qr_data(
            client_private_key=keypair.private_key,
            client_address=client_ip,
            server_public_key=_vpn.server_public_key,
            endpoint=endpoint,
            dns=_vpn.dns,
            awg_params=_vpn.awg_params
        )

        # Generate QR image
        qr_image = generate_qr_code(qr_data_base64)
        
        await status_msg.delete()

        # Send Config File
        config_file = BufferedInputFile(config.encode(), filename=f"{client_name}.conf")
        await message.answer_document(
            config_file,
            caption=f"✅ Клиент `{client_name}` создан!\nIP: `{client_ip}`",
            parse_mode=ParseMode.MARKDOWN
        )

        # Send QR Photo
        qr_photo = BufferedInputFile(qr_image, filename=f"{client_name}_qr.png")
        await message.answer_photo(
            qr_photo,
            caption="📱 QR-код для AmneziaVPN"
        )
        
        # Send Text Key
        vpn_link = f"vpn://{qr_data_base64}"
        await message.answer(
            f"🔑 **Ключ для AmneziaVPN** (нажмите чтобы скопировать):\n\n`{vpn_link}`",
            parse_mode=ParseMode.MARKDOWN
        )

        logger.info(f"Created client: {client_name} ({client_ip})")
        
        # Reset state
        await state.clear()
        
    except Exception as e:
        logger.exception(f"Failed to create client: {e}")
        await message.answer(f"❌ Ошибка при создании: {e}")
        await state.clear()


@router.message(F.text == "🗑 Удалить клиента")
@admin_only
async def start_delete_client(message: Message) -> None:
    """Show client deletion menu."""
    clients = await _db.get_all_clients()
    if not clients:
        await message.answer("Список клиентов пуст.")
        return

    # Create inline keyboard with clients
    keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=f"❌ {c.name}", callback_data=f"del:{c.name}")]
        for c in clients
    ])
    await message.answer("Выберите клиента для удаления (доступ будет закрыт немедленно):", reply_markup=keyboard)


@router.callback_query(F.data.startswith("del:"))
async def process_delete_callback(callback: CallbackQuery):
    """Handle deletion callback."""
    if not callback.data:
        return
        
    client_name = callback.data.split(":")[1]
    
    # Check existance
    if not await _db.client_exists(client_name):
        await callback.answer("Клиент уже удален", show_alert=True)
        await callback.message.delete()
        return

    try:
        # Delete from DB
        await _db.delete_client(client_name)
        
        # FULL SYNC (Remove from config and reload interface)
        await full_sync_server()
        
        await callback.answer(f"Клиент {client_name} удален")
        await callback.message.edit_text(f"✅ Клиент `{client_name}` успешно удален.\nДоступ закрыт.", parse_mode=ParseMode.MARKDOWN)
        logger.info(f"Deleted client: {client_name}")
        
    except Exception as e:
        logger.exception(f"Delete failed: {e}")
        await callback.answer("Ошибка при удалении", show_alert=True)


@router.message(F.text == "📋 Список клиентов")
@router.message(Command("list"))
@admin_only
async def cmd_list(message: Message) -> None:
    """Show list of clients."""
    clients = await _db.get_all_clients()

    if not clients:
        await message.answer("📋 Список клиентов пуст.")
        return

    lines = ["📋 **Список клиентов:**\n"]
    for i, client in enumerate(clients, 1):
        created = client.created_at.strftime("%Y-%m-%d")
        lines.append(f"{i}. `{client.name}` — {client.address}")

    await message.answer("\n".join(lines), parse_mode=ParseMode.MARKDOWN)


@router.message(F.text == "📊 Статистика")
@router.message(Command("stats"))
@admin_only
async def cmd_stats(message: Message) -> None:
    """Show detailed traffic statistics menu."""
    stats_keyboard = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📈 Динамика (24ч)", callback_data="stats:24h")],
        [InlineKeyboardButton(text="📅 По часам (Сутки)", callback_data="stats:daily"),
         InlineKeyboardButton(text="📆 По дням недели", callback_data="stats:weekly")],
        [InlineKeyboardButton(text="👥 Топ пользователей", callback_data="stats:top")]
    ])
    await message.answer("📊 Выберите тип статистики:", reply_markup=stats_keyboard)


@router.callback_query(F.data.startswith("stats:"))
async def process_stats_callback(callback: CallbackQuery):
    """Handle statistics menu callbacks."""
    action = callback.data.split(":")[1]
    chart_img = None
    caption = ""
    filename = "stats.png"

    try:
        # Indicate loading
        await callback.message.edit_text("⏳ Генерирую график...")
        
        if action == "24h":
            data = await _db.get_traffic_series(days=1)
            chart_img = generate_series_chart(data, "Трафик за последние 24 часа")
            caption = "📈 **Динамика загрузки и отдачи за сутки**"
            
        elif action == "daily":
            data = await _db.get_hourly_activity()
            chart_img = generate_hourly_chart(data, "Средняя активность по часам")
            caption = "📅 **Профиль нагрузки по времени суток (0-23)**"
            
        elif action == "weekly":
            data = await _db.get_weekly_activity()
            chart_img = generate_weekly_chart(data, "Активность по дням недели")
            caption = "📆 **Нагрузка по дням недели**"
            
        elif action == "top":
            data = await _db.get_total_traffic_by_client()
            chart_img = generate_traffic_chart(data)
            caption = generate_stats_summary(data)

        if chart_img:
            file = BufferedInputFile(chart_img, filename=filename)
            # Delete "Generate..." message and send photo (edit_media is cleaner but requires InputMediaPhoto)
            await callback.message.delete()
            await callback.message.answer_photo(file, caption=caption, parse_mode=ParseMode.MARKDOWN)
        else:
            await callback.message.edit_text("❌ Нет данных для отображения.")
            
    except Exception as e:
        logger.exception(f"Stats generation failed: {e}")
        # Try to edit message if possible
        try:
            await callback.message.edit_text(f"❌ Ошибка: {e}")
        except:
            await callback.message.answer(f"❌ Ошибка: {e}")
    
    await callback.answer()



@router.message(F.text)
@admin_only
async def unknown_command(message: Message) -> None:
    """Handle unknown messages."""
    await message.answer("❓ Неизвестная команда. Используйте меню.", reply_markup=main_menu)

