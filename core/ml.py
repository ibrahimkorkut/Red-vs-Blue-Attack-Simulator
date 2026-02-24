from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
from sklearn.ensemble import IsolationForest
import joblib

from core.config import Config


class MLAnomalyEngine:
    def __init__(self, config: Config, logger) -> None:
        self._cfg = config
        self._logger = logger

    def _extract_features(self, events: List[Dict[str, Any]]) -> np.ndarray:
        """
        Very simple numeric feature extractor from normalized events.
        This is deliberately generic; you can expand it for richer models.
        """
        feats: list[list[float]] = []
        for e in events:
            md = e.get("metadata", {}) or {}
            feats.append(
                [
                    float(md.get("failed_logins", 0)),
                    float(md.get("unique_src_ips", 0)),
                    float(md.get("bytes", 0)),
                    float(md.get("requests_per_minute", 0)),
                ]
            )
        if not feats:
            return np.zeros((0, 4), dtype=float)
        return np.asarray(feats, dtype=float)

    def train_from_logs(self, dataset_path: str, model_out: str) -> None:
        path = Path(dataset_path)
        if not path.exists():
            raise FileNotFoundError(dataset_path)

        events: List[Dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line))

        X = self._extract_features(events)
        if X.shape[0] == 0:
            self._logger.warning("No events found in dataset for ML training.")
            return

        self._logger.info("Training IsolationForest on %d events.", X.shape[0])
        model = IsolationForest(
            contamination=float(self._cfg.get("ml.contamination", 0.02)),
            random_state=int(self._cfg.get("ml.random_state", 42)),
        )
        model.fit(X)
        joblib.dump(model, model_out)
        self._logger.info("ML model saved to %s.", model_out)

    def score_events(
        self, model_path: str, events: List[Dict[str, Any]]
    ) -> List[float]:
        X = self._extract_features(events)
        if X.shape[0] == 0:
            return []
        model = joblib.load(model_path)
        scores = model.decision_function(X)  # lower = more anomalous
        return scores.tolist()

