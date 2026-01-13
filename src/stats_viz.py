"""
Statistics visualization module.
Generates traffic charts using matplotlib.
"""

import io
import logging
from typing import Optional

import matplotlib
matplotlib.use('Agg')  # Non-interactive backend for server use
import matplotlib.pyplot as plt

logger = logging.getLogger(__name__)


def bytes_to_gb(bytes_count: int) -> float:
    """Convert bytes to gigabytes."""
    return bytes_count / (1024 ** 3)


def format_size(bytes_count: int) -> str:
    """Format bytes to human-readable string."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_count < 1024:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024
    return f"{bytes_count:.2f} PB"


def generate_traffic_chart(
    traffic_data: dict[str, tuple[int, int]],
    title: str = "VPN Traffic by Client"
) -> Optional[bytes]:
    """
    Generate a bar chart showing traffic per client.

    Args:
        traffic_data: Dict of {client_name: (bytes_received, bytes_sent)}
        title: Chart title

    Returns:
        PNG image as bytes, or None if no data
    """
    if not traffic_data:
        logger.warning("No traffic data to visualize")
        return None

    # Prepare data
    # Note: traffic_data is (bytes_received_by_server, bytes_sent_by_server)
    # From client perspective: received_by_server = uploaded, sent_by_server = downloaded
    clients = list(traffic_data.keys())
    uploaded = [bytes_to_gb(traffic_data[c][0]) for c in clients]
    downloaded = [bytes_to_gb(traffic_data[c][1]) for c in clients]

    # Create figure with dark theme for better Telegram visibility
    plt.style.use('dark_background')
    fig, ax = plt.subplots(figsize=(10, 6))

    # Bar positions
    x = range(len(clients))
    width = 0.35

    # Create bars
    bars1 = ax.bar(
        [i - width/2 for i in x],
        downloaded,
        width,
        label='Downloaded',
        color='#4CAF50',  # Green
        alpha=0.8
    )
    bars2 = ax.bar(
        [i + width/2 for i in x],
        uploaded,
        width,
        label='Uploaded',
        color='#2196F3',  # Blue
        alpha=0.8
    )

    # Add value labels on bars
    def add_labels(bars):
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax.annotate(
                    f'{height:.2f}',
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center',
                    va='bottom',
                    fontsize=9,
                    color='white'
                )

    add_labels(bars1)
    add_labels(bars2)

    # Customize chart
    ax.set_xlabel('Client', fontsize=12, color='white')
    ax.set_ylabel('Traffic (GB)', fontsize=12, color='white')
    ax.set_title(title, fontsize=14, fontweight='bold', color='white')
    ax.set_xticks(x)
    ax.set_xticklabels(clients, rotation=45, ha='right', fontsize=10)
    ax.legend(loc='upper right', fontsize=10)

    # Add grid for readability
    ax.yaxis.grid(True, linestyle='--', alpha=0.3)
    ax.set_axisbelow(True)

    # Adjust layout
    plt.tight_layout()

    # Save to bytes
    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=150, facecolor='#1a1a1a', edgecolor='none')
    buf.seek(0)
    plt.close(fig)

    return buf.getvalue()


def generate_stats_summary(traffic_data: dict[str, tuple[int, int]]) -> str:
    """
    Generate text summary of traffic statistics.

    Args:
        traffic_data: Dict of {client_name: (bytes_received, bytes_sent)}

    Returns:
        Formatted text summary
    """
    if not traffic_data:
        return "📊 No traffic data available yet."

    # Note: traffic_data is (bytes_received_by_server, bytes_sent_by_server)
    # From client perspective: received_by_server = uploaded, sent_by_server = downloaded
    total_uploaded = sum(t[0] for t in traffic_data.values())
    total_downloaded = sum(t[1] for t in traffic_data.values())
    total_traffic = total_uploaded + total_downloaded

    lines = [
        "📊 **Traffic Statistics**",
        "",
        f"👥 **Active clients:** {len(traffic_data)}",
        f"📥 **Total downloaded:** {format_size(total_downloaded)}",
        f"📤 **Total uploaded:** {format_size(total_uploaded)}",
        f"📦 **Total traffic:** {format_size(total_traffic)}",
        "",
        "**By client:**",
    ]

    # Sort by total traffic
    sorted_clients = sorted(
        traffic_data.items(),
        key=lambda x: x[1][0] + x[1][1],
        reverse=True
    )

    for i, (name, (server_rx, server_tx)) in enumerate(sorted_clients, 1):
        # server_rx = uploaded by client, server_tx = downloaded by client
        total = server_rx + server_tx
        lines.append(f"{i}. **{name}**: {format_size(total)} (↓{format_size(server_tx)} / ↑{format_size(server_rx)})")

    return "\n".join(lines)


def generate_series_chart(data: list[dict], title: str = "Traffic History (24h)") -> Optional[bytes]:
    """Generate time series line chart."""
    if not data:
        return None

    # Parse data
    # Note: rx/tx from DB is server perspective
    # rx (received by server) = uploaded by client
    # tx (sent by server) = downloaded by client
    from datetime import datetime
    timestamps = [datetime.strptime(d['ts'], "%Y-%m-%d %H:%M:%S") for d in data]
    uploaded = [bytes_to_gb(d['rx']) for d in data]
    downloaded = [bytes_to_gb(d['tx']) for d in data]

    plt.style.use('dark_background')
    fig, ax = plt.subplots(figsize=(10, 6))

    ax.plot(timestamps, downloaded, label='Downloaded', color='#4CAF50', linewidth=2)
    ax.plot(timestamps, uploaded, label='Uploaded', color='#2196F3', linewidth=2)

    # Fill area under curve
    ax.fill_between(timestamps, downloaded, alpha=0.3, color='#4CAF50')
    ax.fill_between(timestamps, uploaded, alpha=0.3, color='#2196F3')

    ax.set_title(title, fontsize=14, fontweight='bold', color='white')
    ax.set_ylabel('Traffic (GB)', fontsize=12, color='white')
    ax.grid(True, linestyle='--', alpha=0.3)
    ax.legend()
    
    # Format x-axis dates
    fig.autofmt_xdate()

    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=150, facecolor='#1a1a1a', edgecolor='none')
    buf.seek(0)
    plt.close(fig)
    return buf.getvalue()


def generate_hourly_chart(data: list[dict], title: str = "Hourly Activity Profile") -> Optional[bytes]:
    """Generate bar chart of traffic by hour of day (0-23)."""
    if not data:
        return None

    # Prepare 24 hours
    hours = list(range(24))
    values = [0] * 24
    
    for d in data:
        h = d['hour']
        if 0 <= h < 24:
            # We use total_bytes here as it represents load
            values[h] = bytes_to_gb(d['total_bytes'])

    plt.style.use('dark_background')
    fig, ax = plt.subplots(figsize=(10, 6))

    ax.bar(hours, values, color='#FFC107', alpha=0.8)

    ax.set_title(title, fontsize=14, fontweight='bold', color='white')
    ax.set_xlabel('Hour of Day (0-23)', fontsize=12, color='white')
    ax.set_ylabel('Total Traffic (GB)', fontsize=12, color='white')
    ax.set_xticks(hours)
    ax.grid(axis='y', linestyle='--', alpha=0.3)

    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=150, facecolor='#1a1a1a', edgecolor='none')
    buf.seek(0)
    plt.close(fig)
    return buf.getvalue()


def generate_weekly_chart(data: list[dict], title: str = "Weekly Activity Profile") -> Optional[bytes]:
    """Generate bar chart of traffic by day of week."""
    if not data:
        return None

    days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
    values = [0] * 7

    for d in data:
        w = d['weekday']
        if 0 <= w < 7:
            values[w] = bytes_to_gb(d['total_bytes'])

    plt.style.use('dark_background')
    fig, ax = plt.subplots(figsize=(10, 6))

    ax.bar(days, values, color='#9C27B0', alpha=0.8)

    ax.set_title(title, fontsize=14, fontweight='bold', color='white')
    ax.set_ylabel('Total Traffic (GB)', fontsize=12, color='white')
    ax.grid(axis='y', linestyle='--', alpha=0.3)

    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=150, facecolor='#1a1a1a', edgecolor='none')
    buf.seek(0)
    plt.close(fig)
    return buf.getvalue()


# --- Server Monitoring Charts ---

def generate_server_cpu_chart(data: list[dict], title: str = "CPU Usage") -> Optional[bytes]:
    """Generate CPU usage time series chart."""
    if not data:
        return None

    from datetime import datetime

    timestamps = []
    cpu_values = []
    for d in data:
        try:
            ts = d['timestamp']
            if isinstance(ts, str):
                # Try different formats
                for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:00", "%Y-%m-%d"]:
                    try:
                        timestamps.append(datetime.strptime(ts, fmt))
                        break
                    except ValueError:
                        continue
                else:
                    timestamps.append(datetime.fromisoformat(ts))
            else:
                timestamps.append(ts)
            cpu_values.append(d['cpu_percent'])
        except Exception as e:
            logger.warning(f"Failed to parse data point: {e}")
            continue

    if not timestamps:
        return None

    plt.style.use('dark_background')
    fig, ax = plt.subplots(figsize=(10, 6))

    ax.plot(timestamps, cpu_values, color='#FF5722', linewidth=2, label='CPU %')
    ax.fill_between(timestamps, cpu_values, alpha=0.3, color='#FF5722')

    # Add threshold line
    ax.axhline(y=80, color='#F44336', linestyle='--', alpha=0.7, label='Alert (80%)')

    ax.set_title(title, fontsize=14, fontweight='bold', color='white')
    ax.set_ylabel('CPU Usage (%)', fontsize=12, color='white')
    ax.set_ylim(0, 100)
    ax.grid(True, linestyle='--', alpha=0.3)
    ax.legend(loc='upper right')

    fig.autofmt_xdate()
    plt.tight_layout()

    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=150, facecolor='#1a1a1a', edgecolor='none')
    buf.seek(0)
    plt.close(fig)
    return buf.getvalue()


def generate_server_memory_chart(data: list[dict], title: str = "Memory Usage") -> Optional[bytes]:
    """Generate memory usage time series chart."""
    if not data:
        return None

    from datetime import datetime

    timestamps = []
    mem_values = []
    for d in data:
        try:
            ts = d['timestamp']
            if isinstance(ts, str):
                for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:00", "%Y-%m-%d"]:
                    try:
                        timestamps.append(datetime.strptime(ts, fmt))
                        break
                    except ValueError:
                        continue
                else:
                    timestamps.append(datetime.fromisoformat(ts))
            else:
                timestamps.append(ts)
            mem_values.append(d['mem_percent'])
        except Exception as e:
            logger.warning(f"Failed to parse data point: {e}")
            continue

    if not timestamps:
        return None

    plt.style.use('dark_background')
    fig, ax = plt.subplots(figsize=(10, 6))

    ax.plot(timestamps, mem_values, color='#2196F3', linewidth=2, label='RAM %')
    ax.fill_between(timestamps, mem_values, alpha=0.3, color='#2196F3')

    # Add threshold line
    ax.axhline(y=90, color='#F44336', linestyle='--', alpha=0.7, label='Alert (90%)')

    ax.set_title(title, fontsize=14, fontweight='bold', color='white')
    ax.set_ylabel('Memory Usage (%)', fontsize=12, color='white')
    ax.set_ylim(0, 100)
    ax.grid(True, linestyle='--', alpha=0.3)
    ax.legend(loc='upper right')

    fig.autofmt_xdate()
    plt.tight_layout()

    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=150, facecolor='#1a1a1a', edgecolor='none')
    buf.seek(0)
    plt.close(fig)
    return buf.getvalue()


def generate_server_disk_chart(data: list[dict], title: str = "Disk Usage") -> Optional[bytes]:
    """Generate disk usage time series chart."""
    if not data:
        return None

    from datetime import datetime

    timestamps = []
    disk_values = []
    for d in data:
        try:
            ts = d['timestamp']
            if isinstance(ts, str):
                for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:00", "%Y-%m-%d"]:
                    try:
                        timestamps.append(datetime.strptime(ts, fmt))
                        break
                    except ValueError:
                        continue
                else:
                    timestamps.append(datetime.fromisoformat(ts))
            else:
                timestamps.append(ts)
            disk_values.append(d['disk_percent'])
        except Exception as e:
            logger.warning(f"Failed to parse data point: {e}")
            continue

    if not timestamps:
        return None

    plt.style.use('dark_background')
    fig, ax = plt.subplots(figsize=(10, 6))

    ax.plot(timestamps, disk_values, color='#4CAF50', linewidth=2, label='Disk %')
    ax.fill_between(timestamps, disk_values, alpha=0.3, color='#4CAF50')

    # Add threshold line
    ax.axhline(y=90, color='#F44336', linestyle='--', alpha=0.7, label='Alert (90%)')

    ax.set_title(title, fontsize=14, fontweight='bold', color='white')
    ax.set_ylabel('Disk Usage (%)', fontsize=12, color='white')
    ax.set_ylim(0, 100)
    ax.grid(True, linestyle='--', alpha=0.3)
    ax.legend(loc='upper right')

    fig.autofmt_xdate()
    plt.tight_layout()

    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=150, facecolor='#1a1a1a', edgecolor='none')
    buf.seek(0)
    plt.close(fig)
    return buf.getvalue()


def generate_server_combined_chart(data: list[dict], title: str = "Server Resources") -> Optional[bytes]:
    """Generate combined chart with CPU, RAM, Disk."""
    if not data:
        return None

    from datetime import datetime

    timestamps = []
    cpu_values = []
    mem_values = []
    disk_values = []

    for d in data:
        try:
            ts = d['timestamp']
            if isinstance(ts, str):
                for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:00", "%Y-%m-%d"]:
                    try:
                        timestamps.append(datetime.strptime(ts, fmt))
                        break
                    except ValueError:
                        continue
                else:
                    timestamps.append(datetime.fromisoformat(ts))
            else:
                timestamps.append(ts)
            cpu_values.append(d['cpu_percent'])
            mem_values.append(d['mem_percent'])
            disk_values.append(d['disk_percent'])
        except Exception as e:
            logger.warning(f"Failed to parse data point: {e}")
            continue

    if not timestamps:
        return None

    plt.style.use('dark_background')
    fig, ax = plt.subplots(figsize=(12, 6))

    ax.plot(timestamps, cpu_values, color='#FF5722', linewidth=2, label='CPU')
    ax.plot(timestamps, mem_values, color='#2196F3', linewidth=2, label='RAM')
    ax.plot(timestamps, disk_values, color='#4CAF50', linewidth=2, label='Disk')

    ax.set_title(title, fontsize=14, fontweight='bold', color='white')
    ax.set_ylabel('Usage (%)', fontsize=12, color='white')
    ax.set_ylim(0, 100)
    ax.grid(True, linestyle='--', alpha=0.3)
    ax.legend(loc='upper right')

    fig.autofmt_xdate()
    plt.tight_layout()

    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=150, facecolor='#1a1a1a', edgecolor='none')
    buf.seek(0)
    plt.close(fig)
    return buf.getvalue()


def generate_server_network_chart(data: list[dict], title: str = "Network Bandwidth") -> Optional[bytes]:
    """Generate network bandwidth time series chart."""
    if not data:
        return None

    from datetime import datetime

    timestamps = []
    sent_values = []
    recv_values = []

    for d in data:
        try:
            ts = d['timestamp']
            if isinstance(ts, str):
                for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:00", "%Y-%m-%d"]:
                    try:
                        timestamps.append(datetime.strptime(ts, fmt))
                        break
                    except ValueError:
                        continue
                else:
                    timestamps.append(datetime.fromisoformat(ts))
            else:
                timestamps.append(ts)
            # Convert bytes to MB
            sent_values.append(d['net_bytes_sent'] / (1024 * 1024))
            recv_values.append(d['net_bytes_recv'] / (1024 * 1024))
        except Exception as e:
            logger.warning(f"Failed to parse data point: {e}")
            continue

    if not timestamps:
        return None

    plt.style.use('dark_background')
    fig, ax = plt.subplots(figsize=(10, 6))

    ax.plot(timestamps, recv_values, color='#4CAF50', linewidth=2, label='Received')
    ax.plot(timestamps, sent_values, color='#2196F3', linewidth=2, label='Sent')
    ax.fill_between(timestamps, recv_values, alpha=0.3, color='#4CAF50')
    ax.fill_between(timestamps, sent_values, alpha=0.3, color='#2196F3')

    ax.set_title(title, fontsize=14, fontweight='bold', color='white')
    ax.set_ylabel('Traffic (MB per interval)', fontsize=12, color='white')
    ax.grid(True, linestyle='--', alpha=0.3)
    ax.legend(loc='upper right')

    fig.autofmt_xdate()
    plt.tight_layout()

    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=150, facecolor='#1a1a1a', edgecolor='none')
    buf.seek(0)
    plt.close(fig)
    return buf.getvalue()
