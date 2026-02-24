from __future__ import annotations

from typing import Any, Dict


def normalize_raw_event(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize heterogeneous raw events (simulation, logs, pcaps) into a
    canonical schema suitable for detection and ML.
    """
    return {
        "timestamp": raw.get("timestamp"),
        "source_type": raw.get("source_type"),
        "category": raw.get("category"),
        "subtype": raw.get("subtype"),
        "src_ip": raw.get("src_ip"),
        "src_port": raw.get("src_port"),
        "dst_ip": raw.get("dst_ip"),
        "dst_port": raw.get("dst_port"),
        "protocol": raw.get("protocol"),
        "username": raw.get("username"),
        "asset_id": raw.get("dst_ip") or raw.get("host"),
        "metadata": raw.get("metadata", {}),
    }

