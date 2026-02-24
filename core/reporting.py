from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.risk import Detection
from core.config import Config


class ReportBuilder:
    def __init__(self, config: Config, logger) -> None:
        self._cfg = config
        self._logger = logger

        templates_dir = Path("core") / "templates"
        self._env = Environment(
            loader=FileSystemLoader(str(templates_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def build_report(
        self,
        events: List[Dict[str, Any]],
        detections: List[Detection],
        per_asset_scores: Dict[str, float],
        global_score: float,
    ) -> Dict[str, Any]:
        return {
            "summary": {
                "global_score": global_score,
                "asset_scores": per_asset_scores,
                "total_events": len(events),
                "total_detections": len(detections),
            },
            "detections": [d.__dict__ for d in detections],
        }

    def save_report(self, report: Dict[str, Any], base_path: str) -> None:
        base = Path(base_path)
        json_path = base.with_suffix(".json")
        html_path = base.with_suffix(".html")

        json_path.parent.mkdir(parents=True, exist_ok=True)
        html_path.parent.mkdir(parents=True, exist_ok=True)

        json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

        tmpl = self._env.get_template("report.html.j2")
        html_content = tmpl.render(report=report)
        html_path.write_text(html_content, encoding="utf-8")

        self._logger.info(
            "Reports written to %s and %s", json_path.as_posix(), html_path.as_posix()
        )

