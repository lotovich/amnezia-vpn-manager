"""
Server monitoring module.
Collects CPU, RAM, Disk, Network metrics using psutil.
"""

import asyncio
import logging
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

import psutil

logger = logging.getLogger(__name__)


@dataclass
class ServerMetrics:
    """Snapshot of server metrics."""
    timestamp: datetime

    # CPU
    cpu_percent: float
    cpu_count: int

    # Memory
    mem_total: int
    mem_used: int
    mem_percent: float

    # Disk
    disk_total: int
    disk_used: int
    disk_percent: float

    # Network (deltas per interval)
    net_bytes_sent: int
    net_bytes_recv: int

    # Load average
    load_1m: Optional[float] = None
    load_5m: Optional[float] = None
    load_15m: Optional[float] = None


class ServerMonitor:
    """Collects server metrics and manages alerts."""

    def __init__(
        self,
        cpu_threshold: float = 80.0,
        mem_threshold: float = 90.0,
        disk_threshold: float = 90.0,
        alert_cooldown: int = 300,  # 5 minutes between same alerts
    ):
        self.cpu_threshold = cpu_threshold
        self.mem_threshold = mem_threshold
        self.disk_threshold = disk_threshold
        self.alert_cooldown = alert_cooldown

        # Track last network counters for delta calculation
        self._last_net_sent: int = 0
        self._last_net_recv: int = 0
        self._first_measurement: bool = True

        # Track last alert times to prevent spam
        self._last_cpu_alert: float = 0
        self._last_mem_alert: float = 0
        self._last_disk_alert: float = 0

    def collect_metrics(self) -> ServerMetrics:
        """Collect current server metrics synchronously."""
        now = datetime.now()

        # CPU (interval=0 for non-blocking)
        cpu_percent = psutil.cpu_percent(interval=0)
        cpu_count = psutil.cpu_count() or 1

        # Memory
        mem = psutil.virtual_memory()

        # Disk (root partition)
        disk = psutil.disk_usage('/')

        # Network - calculate deltas
        net = psutil.net_io_counters()
        if self._first_measurement:
            net_delta_sent = 0
            net_delta_recv = 0
            self._first_measurement = False
        else:
            net_delta_sent = net.bytes_sent - self._last_net_sent
            net_delta_recv = net.bytes_recv - self._last_net_recv
            # Handle counter reset
            if net_delta_sent < 0:
                net_delta_sent = net.bytes_sent
            if net_delta_recv < 0:
                net_delta_recv = net.bytes_recv

        self._last_net_sent = net.bytes_sent
        self._last_net_recv = net.bytes_recv

        # Load average (Linux/macOS only)
        try:
            load = psutil.getloadavg()
            load_1m, load_5m, load_15m = load
        except (AttributeError, OSError):
            load_1m = load_5m = load_15m = None

        return ServerMetrics(
            timestamp=now,
            cpu_percent=cpu_percent,
            cpu_count=cpu_count,
            mem_total=mem.total,
            mem_used=mem.used,
            mem_percent=mem.percent,
            disk_total=disk.total,
            disk_used=disk.used,
            disk_percent=disk.percent,
            net_bytes_sent=net_delta_sent,
            net_bytes_recv=net_delta_recv,
            load_1m=load_1m,
            load_5m=load_5m,
            load_15m=load_15m,
        )

    async def collect_metrics_async(self) -> ServerMetrics:
        """Async wrapper - runs blocking psutil in executor."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.collect_metrics)

    def check_alerts(self, metrics: ServerMetrics) -> list[dict]:
        """
        Check if any thresholds exceeded.
        Returns list of alert dicts with 'type', 'value', 'threshold' keys.
        Respects cooldown period to prevent alert spam.
        """
        now = time.time()
        alerts = []

        # CPU Alert
        if metrics.cpu_percent >= self.cpu_threshold:
            if now - self._last_cpu_alert >= self.alert_cooldown:
                alerts.append({
                    'type': 'cpu',
                    'value': metrics.cpu_percent,
                    'threshold': self.cpu_threshold
                })
                self._last_cpu_alert = now

        # Memory Alert
        if metrics.mem_percent >= self.mem_threshold:
            if now - self._last_mem_alert >= self.alert_cooldown:
                alerts.append({
                    'type': 'memory',
                    'value': metrics.mem_percent,
                    'threshold': self.mem_threshold
                })
                self._last_mem_alert = now

        # Disk Alert
        if metrics.disk_percent >= self.disk_threshold:
            if now - self._last_disk_alert >= self.alert_cooldown:
                alerts.append({
                    'type': 'disk',
                    'value': metrics.disk_percent,
                    'threshold': self.disk_threshold
                })
                self._last_disk_alert = now

        return alerts


def get_uptime_info() -> dict:
    """Get system boot time and uptime."""
    boot_time = psutil.boot_time()
    uptime_seconds = time.time() - boot_time

    days = int(uptime_seconds // 86400)
    hours = int((uptime_seconds % 86400) // 3600)
    minutes = int((uptime_seconds % 3600) // 60)

    return {
        'boot_time': datetime.fromtimestamp(boot_time),
        'uptime_seconds': uptime_seconds,
        'uptime_formatted': f"{days}d {hours}h {minutes}m"
    }
