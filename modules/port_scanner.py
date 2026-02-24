from __future__ import annotations

import socket
import threading
import time
from typing import List, Set

from core.config import Config


def _parse_ports(spec: str) -> List[int]:
    ports: Set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_str, end_str = part.split("-", 1)
            start = int(start_str)
            end = int(end_str)
            for p in range(start, end + 1):
                ports.add(p)
        else:
            ports.add(int(part))
    return sorted(ports)


def safe_tcp_scan(config: Config, logger, target: str, ports_spec: str):
    """
    Simple, rate-limited TCP connect scanner.

    This is intended for defensive assessment of systems you own or
    are explicitly authorised to test.
    """
    ports = _parse_ports(ports_spec)
    max_threads = int(config.get("port_scanner.max_threads", 50))
    rate_limit = float(config.get("port_scanner.rate_limit_per_second", 100))
    timeout = float(config.get("port_scanner.connect_timeout", 1.0))

    open_ports: List[int] = []
    lock = threading.Lock()

    def worker(port: int) -> None:
        nonlocal open_ports
        start = time.time()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((target, port)) == 0:
                    with lock:
                        open_ports.append(port)
        except OSError:
            # Network error or unreachable host: treated as closed.
            pass
        elapsed = time.time() - start
        min_interval = 1.0 / rate_limit if rate_limit > 0 else 0.0
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)

    threads: List[threading.Thread] = []
    for port in ports:
        # Throttle concurrent workers
        while len([t for t in threads if t.is_alive()]) >= max_threads:
            time.sleep(0.01)
        t = threading.Thread(target=worker, args=(port,), daemon=True)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    open_ports.sort()
    logger.info("Open TCP ports on %s: %s", target, open_ports)
    return open_ports

