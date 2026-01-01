"""
Database module for AmneziaWG VPN Manager.
Uses SQLite with aiosqlite for async operations.
"""

import aiosqlite
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class Client:
    """VPN client data model."""
    id: int
    name: str
    public_key: str
    private_key: str
    address: str  # e.g., "10.8.0.2/32"
    created_at: datetime
    is_active: bool = True


@dataclass
class TrafficRecord:
    """Traffic history record."""
    id: int
    client_id: int
    bytes_received: int
    bytes_sent: int
    recorded_at: datetime


class Database:
    """Async SQLite database handler."""

    def __init__(self, db_path: str = "/data/vpn.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    async def init(self) -> None:
        """Initialize database schema."""
        async with aiosqlite.connect(self.db_path) as db:
            # Clients table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS clients (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    public_key TEXT UNIQUE NOT NULL,
                    private_key TEXT NOT NULL,
                    address TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                )
            """)

            # Traffic history table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS traffic_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id INTEGER NOT NULL,
                    bytes_received INTEGER NOT NULL,
                    bytes_sent INTEGER NOT NULL,
                    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (client_id) REFERENCES clients(id)
                )
            """)

            # Last known traffic counters (for delta calculation)
            # WireGuard resets counters on restart, so we track last known values
            await db.execute("""
                CREATE TABLE IF NOT EXISTS traffic_counters (
                    client_id INTEGER PRIMARY KEY,
                    last_bytes_received INTEGER DEFAULT 0,
                    last_bytes_sent INTEGER DEFAULT 0,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (client_id) REFERENCES clients(id)
                )
            """)

            # Index for faster queries
            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_traffic_history_client
                ON traffic_history(client_id)
            """)
            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_traffic_history_time
                ON traffic_history(recorded_at)
            """)

            await db.commit()

    async def add_client(
        self,
        name: str,
        public_key: str,
        private_key: str,
        address: str
    ) -> Client:
        """Add a new VPN client."""
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                """
                INSERT INTO clients (name, public_key, private_key, address)
                VALUES (?, ?, ?, ?)
                """,
                (name, public_key, private_key, address)
            )
            await db.commit()

            # Initialize traffic counter
            await db.execute(
                """
                INSERT INTO traffic_counters (client_id, last_bytes_received, last_bytes_sent)
                VALUES (?, 0, 0)
                """,
                (cursor.lastrowid,)
            )
            await db.commit()

            return Client(
                id=cursor.lastrowid,
                name=name,
                public_key=public_key,
                private_key=private_key,
                address=address,
                created_at=datetime.now(),
                is_active=True
            )

    async def get_client_by_name(self, name: str) -> Optional[Client]:
        """Get client by name."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM clients WHERE name = ?", (name,)
            ) as cursor:
                row = await cursor.fetchone()
                if row:
                    return Client(
                        id=row["id"],
                        name=row["name"],
                        public_key=row["public_key"],
                        private_key=row["private_key"],
                        address=row["address"],
                        created_at=datetime.fromisoformat(row["created_at"]),
                        is_active=bool(row["is_active"])
                    )
        return None

    async def get_client_by_public_key(self, public_key: str) -> Optional[Client]:
        """Get client by public key."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM clients WHERE public_key = ?", (public_key,)
            ) as cursor:
                row = await cursor.fetchone()
                if row:
                    return Client(
                        id=row["id"],
                        name=row["name"],
                        public_key=row["public_key"],
                        private_key=row["private_key"],
                        address=row["address"],
                        created_at=datetime.fromisoformat(row["created_at"]),
                        is_active=bool(row["is_active"])
                    )
        return None

    async def get_all_clients(self) -> list[Client]:
        """Get all active clients."""
        clients = []
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM clients WHERE is_active = 1 ORDER BY id"
            ) as cursor:
                async for row in cursor:
                    clients.append(Client(
                        id=row["id"],
                        name=row["name"],
                        public_key=row["public_key"],
                        private_key=row["private_key"],
                        address=row["address"],
                        created_at=datetime.fromisoformat(row["created_at"]),
                        is_active=bool(row["is_active"])
                    ))
        return clients

    async def get_next_available_ip(self) -> str:
        """Get next available IP address in the 10.8.0.0/24 subnet."""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT address FROM clients ORDER BY id"
            ) as cursor:
                used_ips = set()
                async for row in cursor:
                    # Extract IP number from "10.8.0.X/32"
                    ip = row[0].split("/")[0]
                    last_octet = int(ip.split(".")[-1])
                    used_ips.add(last_octet)

            # Start from .2 (server is .1)
            for i in range(2, 255):
                if i not in used_ips:
                    return f"10.8.0.{i}/32"

            raise ValueError("No available IP addresses in subnet")

    async def update_traffic_counters(
        self,
        client_id: int,
        current_received: int,
        current_sent: int
    ) -> tuple[int, int]:
        """
        Update traffic counters and return delta.
        Handles WireGuard counter resets gracefully.
        Returns (delta_received, delta_sent).
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row

            # Get last known counters
            async with db.execute(
                "SELECT * FROM traffic_counters WHERE client_id = ?",
                (client_id,)
            ) as cursor:
                row = await cursor.fetchone()

            if row:
                last_received = row["last_bytes_received"]
                last_sent = row["last_bytes_sent"]

                # Calculate delta (handle counter reset)
                if current_received >= last_received:
                    delta_received = current_received - last_received
                else:
                    # Counter was reset, use current value as delta
                    delta_received = current_received

                if current_sent >= last_sent:
                    delta_sent = current_sent - last_sent
                else:
                    delta_sent = current_sent
            else:
                # First measurement
                delta_received = current_received
                delta_sent = current_sent

            # Update counters
            await db.execute(
                """
                INSERT OR REPLACE INTO traffic_counters
                (client_id, last_bytes_received, last_bytes_sent, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                """,
                (client_id, current_received, current_sent)
            )

            # Record to history if there's actual traffic
            if delta_received > 0 or delta_sent > 0:
                await db.execute(
                    """
                    INSERT INTO traffic_history (client_id, bytes_received, bytes_sent)
                    VALUES (?, ?, ?)
                    """,
                    (client_id, delta_received, delta_sent)
                )

            await db.commit()

            return delta_received, delta_sent

    async def get_total_traffic_by_client(self) -> dict[str, tuple[int, int]]:
        """
        Get total traffic per client.
        Returns dict: {client_name: (total_received, total_sent)}
        """
        result = {}
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """
                SELECT
                    c.name,
                    COALESCE(SUM(t.bytes_received), 0) as total_received,
                    COALESCE(SUM(t.bytes_sent), 0) as total_sent
                FROM clients c
                LEFT JOIN traffic_history t ON c.id = t.client_id
                WHERE c.is_active = 1
                GROUP BY c.id, c.name
                ORDER BY (total_received + total_sent) DESC
                """
            ) as cursor:
                async for row in cursor:
                    result[row["name"]] = (row["total_received"], row["total_sent"])

        return result

    async def delete_client(self, name: str) -> bool:
        """Soft-delete a client (mark as inactive)."""
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                "UPDATE clients SET is_active = 0 WHERE name = ?",
                (name,)
            )
            await db.commit()
            return cursor.rowcount > 0

    async def client_exists(self, name: str) -> bool:
        """Check if client with given name exists."""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT 1 FROM clients WHERE name = ? AND is_active = 1",
                (name,)
            ) as cursor:
                return await cursor.fetchone() is not None
