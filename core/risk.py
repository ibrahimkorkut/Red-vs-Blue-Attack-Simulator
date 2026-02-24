from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from core.config import Config


@dataclass
class Detection:
    asset_id: str
    severity: str
    confidence: float
    frequency: int
    category: str
    metadata: Dict


SEVERITY_SCORES: Dict[str, int] = {
    "low": 1,
    "medium": 3,
    "high": 7,
    "critical": 10,
}


class RiskEngine:
    def __init__(self, config: Config) -> None:
        self._cfg = config

    def _score_detection(self, detection: Detection, asset_crit: float) -> float:
        weights = self._cfg.get("risk.weights", {}) or {}
        ws = float(weights.get("severity", 0.4))
        wc = float(weights.get("confidence", 0.2))
        wf = float(weights.get("frequency", 0.2))
        wa = float(weights.get("asset_criticality", 0.2))

        sev_score = float(SEVERITY_SCORES.get(detection.severity, 1))
        freq = max(1, detection.frequency or 1)
        norm_freq = min(1.0, freq ** 0.2 / 2.0)

        return (
            sev_score * ws
            + float(detection.confidence) * wc
            + norm_freq * wf
            + float(asset_crit) * wa
        )

    def aggregate(
        self, detections: List[Detection], asset_crit_map: Dict[str, float] | None = None
    ):
        asset_crit_map = asset_crit_map or {}
        per_asset: Dict[str, float] = {}

        for d in detections:
            crit = float(asset_crit_map.get(d.asset_id, 0.5))
            score = self._score_detection(d, crit)
            per_asset[d.asset_id] = per_asset.get(d.asset_id, 0.0) + score

        total = float(sum(per_asset.values()))
        # Smooth mapping to 0–100
        global_score = 100.0 * (1.0 - pow(2.718281828, -0.01 * total))
        return per_asset, global_score

