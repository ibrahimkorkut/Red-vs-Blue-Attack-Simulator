from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from core.config import Config
from core.events import EventBus
from core.normalization import normalize_raw_event
from core.reporting import ReportBuilder
from core.risk import Detection, RiskEngine


class BlueAgent:
    """
    Blue Defense Agent.

    Consumes normalized events from synthetic or real datasets, runs
    basic detection logic, and produces JSON + HTML reports.
    """

    def __init__(self, config: Config, logger) -> None:
        self._cfg = config
        self._logger = logger
        self.bus = EventBus()
        self._risk_engine = RiskEngine(config)
        self._report_builder = ReportBuilder(config, logger)

    def analyze_logs(self, input_path: str, output_base: str) -> None:
        path = Path(input_path)
        if not path.exists():
            raise FileNotFoundError(input_path)

        files: List[Path]
        if path.is_file():
            files = [path]
        else:
            files = sorted(path.glob("*.jsonl"))

        events: List[Dict[str, Any]] = []
        for file in files:
            self._logger.info("Loading events from %s", file.as_posix())
            for line in file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                raw = json.loads(line)
                events.append(normalize_raw_event(raw))

        detections = self._run_detectors(events)
        per_asset, global_score = self._risk_engine.aggregate(detections, {})

        report = self._report_builder.build_report(
            events=events,
            detections=detections,
            per_asset_scores=per_asset,
            global_score=global_score,
        )
        self._report_builder.save_report(report, output_base)

    # --- Simple built-in detectors ------------------------------------------

    def _run_detectors(self, events: List[Dict[str, Any]]) -> List[Detection]:
        detections: List[Detection] = []
        detections.extend(self._detect_bruteforce(events))
        # Placeholders for additional detectors:
        # detections.extend(self._detect_credential_leaks(events))
        # detections.extend(self._detect_wifi_anomalies(events))
        # detections.extend(self._detect_web_misconfig(events))
        return detections

    def _detect_bruteforce(self, events: List[Dict[str, Any]]) -> List[Detection]:
        key_counts: Dict[str, int] = {}
        for e in events:
            if e.get("category") == "auth" and e.get("subtype") == "ssh_bruteforce":
                dst = e.get("dst_ip") or "unknown"
                user = e.get("username") or "-"
                key = f"{dst}:{user}"
                key_counts[key] = key_counts.get(key, 0) + 1

        detections: List[Detection] = []
        for key, count in key_counts.items():
            if count < 5:
                continue
            asset, user = key.split(":", 1)
            severity = "medium" if count < 20 else "high"
            detections.append(
                Detection(
                    asset_id=asset,
                    severity=severity,
                    confidence=0.9,
                    frequency=count,
                    category="brute_force",
                    metadata={"username": user},
                )
            )
        return detections

