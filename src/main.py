"""
AmneziaWG VPN Manager - Main entry point.
Starts the Telegram bot and background traffic collector.
"""

import asyncio
import logging
import os
import sys

from dotenv import load_dotenv
from aiogram import Bot, Dispatcher
from aiogram.enums import ParseMode
from aiogram.client.default import DefaultBotProperties

from database import Database
from vpn_manager import VPNManager
from bot_handlers import setup_handlers

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Reduce noise from libraries
logging.getLogger("aiogram").setLevel(logging.WARNING)
logging.getLogger("aiosqlite").setLevel(logging.WARNING)

# Configuration
BOT_TOKEN = os.getenv("BOT_TOKEN")
VPN_HOST = os.getenv("VPN_HOST", "vpn.example.com")
VPN_PORT = int(os.getenv("VPN_PORT", "51820"))
VPN_DNS = os.getenv("VPN_DNS", "1.1.1.1")
STATS_INTERVAL = int(os.getenv("STATS_INTERVAL", "60"))  # seconds


async def traffic_collector(db: Database, vpn: VPNManager) -> None:
    """
    Background task that collects traffic statistics.
    Runs every STATS_INTERVAL seconds.
    """
    logger.info(f"Traffic collector started (interval: {STATS_INTERVAL}s)")

    while True:
        try:
            await asyncio.sleep(STATS_INTERVAL)

            # Check if interface is up
            if not await vpn.is_interface_up():
                logger.debug("VPN interface not up, skipping stats collection")
                continue

            # Get current stats from interface
            stats = await vpn.get_interface_stats()

            if not stats:
                logger.debug("No peer stats available")
                continue

            # Update database for each peer
            for peer_stats in stats:
                # Find client by public key
                client = await db.get_client_by_public_key(peer_stats.public_key)
                if client:
                    delta_rx, delta_tx = await db.update_traffic_counters(
                        client_id=client.id,
                        current_received=peer_stats.bytes_received,
                        current_sent=peer_stats.bytes_sent
                    )
                    if delta_rx > 0 or delta_tx > 0:
                        logger.debug(
                            f"Traffic for {client.name}: "
                            f"+{delta_rx} bytes RX, +{delta_tx} bytes TX"
                        )
                    
                    # --- Session Tracking ---
                    now = datetime.now()
                    # A peer is considered "online" if had a handshake within the last 5 minutes
                    is_online = (time.time() - peer_stats.latest_handshake) < 300 if peer_stats.latest_handshake > 0 else False
                    
                    active_session = await db.get_active_session(client.id)
                    
                    if is_online and not active_session:
                        # Start new session
                        start_time = datetime.fromtimestamp(peer_stats.latest_handshake) if peer_stats.latest_handshake > 0 else now
                        await db.start_session(client.id, start_time)
                        logger.info(f"FSM: Session started for {client.name} at {start_time}")
                        
                    elif not is_online and active_session:
                        # End current session
                        # We use the handshake time as end time as it's the last confirmed activity
                        end_time = datetime.fromtimestamp(peer_stats.latest_handshake) if peer_stats.latest_handshake > 0 else now
                        await db.end_session(client.id, end_time)
                        logger.info(f"FSM: Session ended for {client.name} at {end_time}")

        except asyncio.CancelledError:
            logger.info("Traffic collector stopped")
            raise
        except Exception as e:
            logger.exception(f"Error in traffic collector: {e}")
            # Continue running despite errors


async def main() -> None:
    """Main entry point."""
    # Validate configuration
    if not BOT_TOKEN:
        logger.error("BOT_TOKEN environment variable is not set!")
        sys.exit(1)

    admin_ids = os.getenv("ADMIN_IDS", "")
    if not admin_ids:
        logger.error("ADMIN_IDS environment variable is not set!")
        sys.exit(1)

    logger.info("=" * 50)
    logger.info("AmneziaWG VPN Manager starting...")
    logger.info(f"VPN Host: {VPN_HOST}")
    logger.info(f"VPN Port: {VPN_PORT}")
    logger.info(f"Admin IDs: {admin_ids}")
    logger.info("=" * 50)

    # Initialize database
    db = Database()
    await db.init()
    logger.info("Database initialized")

    # Initialize VPN manager
    vpn = VPNManager(
        vpn_host=VPN_HOST,
        vpn_port=VPN_PORT,
        dns=VPN_DNS,
    )
    logger.info("VPN manager initialized")

    # Initialize bot
    bot = Bot(
        token=BOT_TOKEN,
        default=DefaultBotProperties(parse_mode=ParseMode.MARKDOWN)
    )
    dp = Dispatcher()

    # Setup handlers
    router = setup_handlers(db, vpn)
    dp.include_router(router)

    # Initial Server Sync: Restore state from DB to Config File
    logger.info("Performing initial server synchronization from DB...")
    try:
        current_clients = await db.get_all_clients()
        # Convert to dicts for VPNManager
        clients_dicts = [{"public_key": c.public_key, "address": c.address} for c in current_clients]
        
        # Rewrite awg0.conf and sync interface
        vpn.update_server_config_file(clients_dicts)
        
        if await vpn.sync_config():
             logger.info(f"Initial sync successful. {len(current_clients)} peers active.")
        else:
             logger.error("Initial sync failed!")
             
    except Exception as e:
        logger.exception(f"Initial sync error: {e}")

    # Start traffic collector in background
    collector_task = asyncio.create_task(traffic_collector(db, vpn))

    try:
        # Start polling
        logger.info("Bot started, waiting for commands...")
        await dp.start_polling(bot, allowed_updates=["message", "callback_query"])

    finally:
        # Cleanup
        collector_task.cancel()
        try:
            await collector_task
        except asyncio.CancelledError:
            pass
        await bot.session.close()
        logger.info("Bot stopped")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Received interrupt signal, shutting down...")
