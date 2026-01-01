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
    clients = list(traffic_data.keys())
    received = [bytes_to_gb(traffic_data[c][0]) for c in clients]
    sent = [bytes_to_gb(traffic_data[c][1]) for c in clients]

    # Create figure with dark theme for better Telegram visibility
    plt.style.use('dark_background')
    fig, ax = plt.subplots(figsize=(10, 6))

    # Bar positions
    x = range(len(clients))
    width = 0.35

    # Create bars
    bars1 = ax.bar(
        [i - width/2 for i in x],
        received,
        width,
        label='Downloaded (RX)',
        color='#4CAF50',  # Green
        alpha=0.8
    )
    bars2 = ax.bar(
        [i + width/2 for i in x],
        sent,
        width,
        label='Uploaded (TX)',
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

    total_received = sum(t[0] for t in traffic_data.values())
    total_sent = sum(t[1] for t in traffic_data.values())
    total_traffic = total_received + total_sent

    lines = [
        "📊 **Traffic Statistics**",
        "",
        f"👥 **Active clients:** {len(traffic_data)}",
        f"📥 **Total downloaded:** {format_size(total_received)}",
        f"📤 **Total uploaded:** {format_size(total_sent)}",
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

    for i, (name, (rx, tx)) in enumerate(sorted_clients, 1):
        total = rx + tx
        lines.append(f"{i}. **{name}**: {format_size(total)} (↓{format_size(rx)} / ↑{format_size(tx)})")

    return "\n".join(lines)
