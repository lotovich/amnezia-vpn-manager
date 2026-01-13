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

            # Sessions table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id INTEGER NOT NULL,
                    start_at TIMESTAMP NOT NULL,
                    end_at TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
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
            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_sessions_client
                ON sessions(client_id)
            """)

            # Server stats table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS server_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    cpu_percent REAL NOT NULL,
                    cpu_count INTEGER NOT NULL,
                    mem_total INTEGER NOT NULL,
                    mem_used INTEGER NOT NULL,
                    mem_percent REAL NOT NULL,
                    disk_total INTEGER NOT NULL,
                    disk_used INTEGER NOT NULL,
                    disk_percent REAL NOT NULL,
                    net_bytes_sent INTEGER NOT NULL,
                    net_bytes_recv INTEGER NOT NULL,
                    load_1m REAL,
                    load_5m REAL,
                    load_15m REAL
                )
            """)

            # Server events table (start/stop/alerts)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS server_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    details TEXT
                )
            """)

            # Indexes for server stats
            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_server_stats_timestamp
                ON server_stats(timestamp)
            """)
            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_server_events_time
                ON server_events(event_time)
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

            is_first_measurement = False
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
                # First measurement - treat as initialization
                # We return 0 delta to avoid recording historical traffic as current
                delta_received = 0
                delta_sent = 0
                is_first_measurement = True

            # Update counters
            await db.execute(
                """
                INSERT OR REPLACE INTO traffic_counters
                (client_id, last_bytes_received, last_bytes_sent, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                """,
                (client_id, current_received, current_sent)
            )

            # Record to history if there's actual traffic AND it's not the initialization step
            if (delta_received > 0 or delta_sent > 0) and not is_first_measurement:
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

    async def get_client_total_traffic(self, client_id: int) -> tuple[int, int]:
        """
        Get total traffic for a single client.
        Returns (total_received, total_sent).
        """
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                """
                SELECT 
                    COALESCE(SUM(bytes_received), 0),
                    COALESCE(SUM(bytes_sent), 0)
                FROM traffic_history
                WHERE client_id = ?
                """,
                (client_id,)
            ) as cursor:
                row = await cursor.fetchone()
                return row[0], row[1]

    async def delete_client(self, name: str) -> bool:
        """Delete a client completely (hard delete)."""
        async with aiosqlite.connect(self.db_path) as db:
            # Get client ID first
            async with db.execute(
                "SELECT id FROM clients WHERE name = ?", (name,)
            ) as cursor:
                row = await cursor.fetchone()
                if not row:
                    return False
                client_id = row[0]

            # Delete traffic history
            await db.execute(
                "DELETE FROM traffic_history WHERE client_id = ?",
                (client_id,)
            )
            # Delete traffic counters
            await db.execute(
                "DELETE FROM traffic_counters WHERE client_id = ?",
                (client_id,)
            )
            # Delete client
            await db.execute(
                "DELETE FROM clients WHERE id = ?",
                (client_id,)
            )
            await db.commit()
            return True

    async def client_exists(self, name: str) -> bool:
        """Check if client with given name exists."""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT 1 FROM clients WHERE name = ?",
                (name,)
            ) as cursor:
                return await cursor.fetchone() is not None
    async def get_traffic_series(self, days: int = 1, client_id: Optional[int] = None) -> list[dict]:
        """
        Get traffic history grouped by hour for the last N days.
        Returns list of {timestamp, rx, tx}.
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            
            # Format time to hour precision
            query = """
                SELECT 
                    strftime('%Y-%m-%d %H:00:00', recorded_at) as ts,
                    SUM(bytes_received) as rx,
                    SUM(bytes_sent) as tx
                FROM traffic_history
                WHERE recorded_at >= datetime('now', ?)
            """
            params = [f"-{days} days"]
            
            if client_id:
                query += " AND client_id = ?"
                params.append(client_id)
                
            query += " GROUP BY ts ORDER BY ts"
            
            async with db.execute(query, tuple(params)) as cursor:
                return [dict(row) for row in await cursor.fetchall()]

    async def get_traffic_series_range(self, start_date: str, end_date: str, client_id: Optional[int] = None) -> list[dict]:
        """
        Get traffic history grouped by hour for a specific date range.
        Dates should be 'YYYY-MM-DD'.
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            
            # We append times to date strings to cover the full range
            start_ts = f"{start_date} 00:00:00"
            end_ts = f"{end_date} 23:59:59"
            
            query = """
                SELECT 
                    strftime('%Y-%m-%d %H:00:00', recorded_at) as ts,
                    SUM(bytes_received) as rx,
                    SUM(bytes_sent) as tx
                FROM traffic_history
                WHERE recorded_at BETWEEN ? AND ?
            """
            params = [start_ts, end_ts]
            
            if client_id:
                query += " AND client_id = ?"
                params.append(client_id)
                
            query += " GROUP BY ts ORDER BY ts"
            
            async with db.execute(query, tuple(params)) as cursor:
                return [dict(row) for row in await cursor.fetchall()]

    async def get_hourly_activity(self, client_id: Optional[int] = None) -> list[dict]:
        """
        Get average traffic volume aggregated by hour of day (0-23).
        Returns list of {hour, total_bytes}.
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            
            query = """
                SELECT 
                    cast(strftime('%H', recorded_at) as int) as hour,
                    AVG(bytes_received + bytes_sent) as avg_bytes,
                    SUM(bytes_received + bytes_sent) as total_bytes
                FROM traffic_history
            """
            params = []
            
            if client_id:
                query += " WHERE client_id = ?"
                params.append(client_id)
                
            query += " GROUP BY hour ORDER BY hour"
            
            async with db.execute(query, tuple(params)) as cursor:
                return [dict(row) for row in await cursor.fetchall()]

    async def get_weekly_activity(self, client_id: Optional[int] = None) -> list[dict]:
        """
        Get traffic volume aggregated by day of week (0=Sunday, 6=Saturday).
        Returns list of {weekday, total_bytes}.
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            
            # strftime %w gives 0-6 (Sunday-Saturday)
            query = """
                SELECT 
                    cast(strftime('%w', recorded_at) as int) as weekday,
                    SUM(bytes_received + bytes_sent) as total_bytes
                FROM traffic_history
            """
            params = []
            
            if client_id:
                query += " WHERE client_id = ?"
                params.append(client_id)
                
            query += " GROUP BY weekday ORDER BY weekday"
            
            async with db.execute(query, tuple(params)) as cursor:
                return [dict(row) for row in await cursor.fetchall()]

    # --- Session Management ---

    async def get_active_session(self, client_id: int) -> Optional[dict]:
        """Get the currently active session for a client."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM sessions WHERE client_id = ? AND is_active = 1 LIMIT 1",
                (client_id,)
            ) as cursor:
                row = await cursor.fetchone()
                return dict(row) if row else None

    async def start_session(self, client_id: int, start_at: datetime) -> None:
        """Create a new active session."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO sessions (client_id, start_at, is_active) VALUES (?, ?, 1)",
                (client_id, start_at.isoformat())
            )
            await db.commit()

    async def end_session(self, client_id: int, end_at: datetime) -> None:
        """Close the active session for a client."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "UPDATE sessions SET end_at = ?, is_active = 0 WHERE client_id = ? AND is_active = 1",
                (end_at.isoformat(), client_id)
            )
            await db.commit()

    async def get_last_session(self, client_id: int) -> Optional[dict]:
        """Get the most recently completed or currently active session."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM sessions WHERE client_id = ? ORDER BY start_at DESC LIMIT 1",
                (client_id,)
            ) as cursor:
                row = await cursor.fetchone()
                return dict(row) if row else None

    async def get_average_session_duration(self, client_id: int, days: Optional[int] = None, minutes: Optional[int] = None) -> float:
        """
        Get average session duration in minutes for a specific period.
        """
        async with aiosqlite.connect(self.db_path) as db:
            query = "SELECT AVG(strftime('%s', end_at) - strftime('%s', start_at)) FROM sessions WHERE client_id = ? AND end_at IS NOT NULL"
            params = [client_id]
            
            if days:
                query += " AND start_at >= datetime('now', ?)"
                params.append(f"-{days} days")
            elif minutes:
                query += " AND start_at >= datetime('now', ?)"
                params.append(f"-{minutes} minutes")
            
            async with db.execute(query, tuple(params)) as cursor:
                row = await cursor.fetchone()
                # row[0] is average seconds
                return (row[0] / 60.0) if row and row[0] is not None else 0.0

    async def get_minute_traffic_series(self, client_id: Optional[int] = None, minutes: int = 60) -> list[dict]:
        """
        Get traffic history grouped by minute for the last N minutes.
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row

            query = """
                SELECT
                    strftime('%Y-%m-%d %H:%M:00', recorded_at) as ts,
                    SUM(bytes_received) as rx,
                    SUM(bytes_sent) as tx
                FROM traffic_history
                WHERE recorded_at >= datetime('now', ?)
            """
            params = [f"-{minutes} minutes"]

            if client_id:
                query += " AND client_id = ?"
                params.append(client_id)

            query += " GROUP BY ts ORDER BY ts"

            async with db.execute(query, tuple(params)) as cursor:
                return [dict(row) for row in await cursor.fetchall()]

    # --- Server Monitoring ---

    async def save_server_metrics(self, metrics) -> None:
        """Save server metrics snapshot to database."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO server_stats (
                    timestamp, cpu_percent, cpu_count,
                    mem_total, mem_used, mem_percent,
                    disk_total, disk_used, disk_percent,
                    net_bytes_sent, net_bytes_recv,
                    load_1m, load_5m, load_15m
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    metrics.timestamp.isoformat(),
                    metrics.cpu_percent,
                    metrics.cpu_count,
                    metrics.mem_total,
                    metrics.mem_used,
                    metrics.mem_percent,
                    metrics.disk_total,
                    metrics.disk_used,
                    metrics.disk_percent,
                    metrics.net_bytes_sent,
                    metrics.net_bytes_recv,
                    metrics.load_1m,
                    metrics.load_5m,
                    metrics.load_15m,
                )
            )
            await db.commit()

    async def get_server_stats_series(
        self,
        minutes: Optional[int] = None,
        days: Optional[int] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None
    ) -> list[dict]:
        """
        Get server stats time series.
        Returns list of dicts with metrics.
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row

            if minutes:
                query = """
                    SELECT * FROM server_stats
                    WHERE timestamp >= datetime('now', ?)
                    ORDER BY timestamp
                """
                params = (f"-{minutes} minutes",)
            elif days:
                query = """
                    SELECT * FROM server_stats
                    WHERE timestamp >= datetime('now', ?)
                    ORDER BY timestamp
                """
                params = (f"-{days} days",)
            elif start_date and end_date:
                query = """
                    SELECT * FROM server_stats
                    WHERE timestamp BETWEEN ? AND ?
                    ORDER BY timestamp
                """
                params = (f"{start_date} 00:00:00", f"{end_date} 23:59:59")
            else:
                # Default: last 24 hours
                query = """
                    SELECT * FROM server_stats
                    WHERE timestamp >= datetime('now', '-1 day')
                    ORDER BY timestamp
                """
                params = ()

            async with db.execute(query, params) as cursor:
                return [dict(row) for row in await cursor.fetchall()]

    async def get_server_stats_aggregated(
        self,
        days: Optional[int] = None,
        group_by: str = 'hour'
    ) -> list[dict]:
        """
        Get aggregated server stats (by hour or day).
        Used for long periods (30 days, all time).
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row

            if group_by == 'day':
                time_format = '%Y-%m-%d'
            else:  # hour
                time_format = '%Y-%m-%d %H:00'

            query = f"""
                SELECT
                    strftime('{time_format}', timestamp) as timestamp,
                    AVG(cpu_percent) as cpu_percent,
                    MAX(cpu_percent) as cpu_max,
                    AVG(cpu_count) as cpu_count,
                    AVG(mem_total) as mem_total,
                    AVG(mem_used) as mem_used,
                    AVG(mem_percent) as mem_percent,
                    MAX(mem_percent) as mem_max,
                    AVG(disk_total) as disk_total,
                    AVG(disk_used) as disk_used,
                    AVG(disk_percent) as disk_percent,
                    SUM(net_bytes_sent) as net_bytes_sent,
                    SUM(net_bytes_recv) as net_bytes_recv,
                    AVG(load_1m) as load_1m,
                    AVG(load_5m) as load_5m,
                    AVG(load_15m) as load_15m
                FROM server_stats
            """
            params = []

            if days:
                query += " WHERE timestamp >= datetime('now', ?)"
                params.append(f"-{days} days")

            query += f" GROUP BY strftime('{time_format}', timestamp) ORDER BY timestamp"

            async with db.execute(query, tuple(params)) as cursor:
                return [dict(row) for row in await cursor.fetchall()]

    async def get_server_stats_latest(self) -> Optional[dict]:
        """Get most recent server stats."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM server_stats ORDER BY timestamp DESC LIMIT 1"
            ) as cursor:
                row = await cursor.fetchone()
                return dict(row) if row else None

    async def get_server_stats_peaks(self, days: int = 7) -> dict:
        """
        Get peak values for server metrics over specified period.
        Returns dict with max and avg values.
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """
                SELECT
                    MAX(cpu_percent) as peak_cpu,
                    MAX(mem_percent) as peak_mem,
                    MAX(disk_percent) as peak_disk,
                    MAX(net_bytes_sent) as peak_net_sent,
                    MAX(net_bytes_recv) as peak_net_recv,
                    AVG(cpu_percent) as avg_cpu,
                    AVG(mem_percent) as avg_mem,
                    AVG(disk_percent) as avg_disk
                FROM server_stats
                WHERE timestamp >= datetime('now', ?)
                """,
                (f"-{days} days",)
            ) as cursor:
                row = await cursor.fetchone()
                return dict(row) if row else {}

    async def record_server_event(self, event_type: str, details: dict = None) -> None:
        """Record server event (start, stop, alert)."""
        import json
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT INTO server_events (event_type, details) VALUES (?, ?)",
                (event_type, json.dumps(details) if details else None)
            )
            await db.commit()

    async def get_server_events(self, days: int = 30, event_type: Optional[str] = None) -> list[dict]:
        """Get server events history."""
        import json
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row

            query = """
                SELECT * FROM server_events
                WHERE event_time >= datetime('now', ?)
            """
            params = [f"-{days} days"]

            if event_type:
                query += " AND event_type = ?"
                params.append(event_type)

            query += " ORDER BY event_time DESC"

            async with db.execute(query, tuple(params)) as cursor:
                results = []
                async for row in cursor:
                    d = dict(row)
                    if d.get('details'):
                        try:
                            d['details'] = json.loads(d['details'])
                        except json.JSONDecodeError:
                            pass
                    results.append(d)
                return results

    async def cleanup_old_server_stats(self, days: int = 365) -> int:
        """
        Delete server stats older than specified days.
        Returns number of deleted rows.
        """
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                "DELETE FROM server_stats WHERE timestamp < datetime('now', ?)",
                (f"-{days} days",)
            )
            await db.commit()
            return cursor.rowcount
