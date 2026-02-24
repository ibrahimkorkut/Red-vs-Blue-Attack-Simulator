from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Dict, Iterable

from core.events import Event, EventBus
from core.config import Config


class RedAgent:
    """
    Red Simulation Agent.

    Generates synthetic attack-style patterns as structured events/logs only.
    No real exploits, credential harvesting, or network disruption are performed.
    """

    def __init__(self, config: Config, logger) -> None:
        self._cfg = config
        self._logger = logger
        self.bus = EventBus()
        self._out_dir = Path("logs") / "simulations"
        self._out_dir.mkdir(parents=True, exist_ok=True)

    def run_scenario(self, scenario: str, count: int = 100) -> None:
        self._logger.info("Running simulation scenario=%s count=%d", scenario, count)
        generator = getattr(self, f"_simulate_{scenario}", None)
        if generator is None:
            raise ValueError(f"Unsupported scenario: {scenario}")

        outfile = self._out_dir / f"{scenario}.jsonl"
        with outfile.open("w", encoding="utf-8") as f:
            for event in generator(count):
                self.bus.publish(event)
                f.write(json.dumps(event.to_dict()) + "\n")

        self._logger.info("Simulation written to %s", outfile.as_posix())

    # --- Synthetic scenarios -------------------------------------------------

    def _simulate_brute_force(self, count: int) -> Iterable[Event]:
        for _ in range(count):
            payload: Dict[str, object] = {
                "source_type": "simulation",
                "category": "auth",
                "subtype": "ssh_bruteforce",
                "src_ip": f"203.0.113.{random.randint(1, 254)}",
                "dst_ip": "192.168.1.10",
                "username": random.choice(["root", "admin", "test"]),
                "status": "failed",
                "metadata": {
                    "auth_service": "sshd",
                    "method": "password",
                    "sim_scenario": "bf-ssh-001",
                },
            }
            yield Event.create("synthetic.auth", payload)

    def _simulate_credential_stuffing(self, count: int) -> Iterable[Event]:
        creds = [("user1", "pwd1"), ("user2", "pwd1"), ("user3", "pwd1")]
        for i in range(count):
            username, _ = random.choice(creds)
            payload: Dict[str, object] = {
                "source_type": "simulation",
                "category": "auth",
                "subtype": "credential_stuffing",
                "src_ip": f"198.51.100.{random.randint(1, 254)}",
                "dst_ip": "192.168.1.20",
                "username": username,
                "status": "failed",
                "metadata": {
                    "sim_scenario": "cred-stuff-001",
                    "attempt_index": i,
                },
            }
            yield Event.create("synthetic.auth", payload)

    def _simulate_port_scan(self, count: int) -> Iterable[Event]:
        base_ports = list(range(20, 120))
        for i in range(min(count, len(base_ports))):
            port = base_ports[i]
            payload: Dict[str, object] = {
                "source_type": "simulation",
                "category": "network",
                "subtype": "port_scan",
                "src_ip": "203.0.113.50",
                "dst_ip": "192.168.1.10",
                "dst_port": port,
                "protocol": "tcp",
                "metadata": {
                    "scan_pattern": "sequential",
                    "sim_scenario": "port-scan-001",
                },
            }
            yield Event.create("synthetic.net", payload)

    def _simulate_web_injection(self, count: int) -> Iterable[Event]:
        payloads = [
            "SELECT * FROM users WHERE id='1' OR '1'='1'",
            "<script>alert('xss')</script>",
            "'; DROP TABLE users; --",
        ]
        for _ in range(count):
            payload: Dict[str, object] = {
                "source_type": "simulation",
                "category": "web",
                "subtype": "injection_attempt",
                "src_ip": f"203.0.113.{random.randint(10, 200)}",
                "dst_ip": "192.168.1.30",
                "metadata": {
                    "http_method": "GET",
                    "path": "/search",
                    "param": "q",
                    "payload": random.choice(payloads),
                    "sim_scenario": "web-inject-001",
                },
            }
            yield Event.create("synthetic.web", payload)

    def _simulate_wifi_deauth(self, count: int) -> Iterable[Event]:
        for _ in range(count):
            payload: Dict[str, object] = {
                "source_type": "simulation",
                "category": "wireless",
                "subtype": "wifi_deauth",
                "metadata": {
                    "frame_type": "management",
                    "subtype": "deauth",
                    "bssid": "00:11:22:33:44:55",
                    "client_mac": f"AA:BB:CC:DD:EE:{random.randint(0, 255):02X}",
                    "reason_code": random.choice([1, 4, 7]),
                    "sim_scenario": "wifi-deauth-001",
                },
            }
            yield Event.create("synthetic.wifi", payload)

