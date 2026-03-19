"""MITRE ATT&CK Navigator layer generation."""

from __future__ import annotations

import json
from pathlib import Path

import structlog

from core.models import ScanResult, Severity, Status

log = structlog.get_logger("mitre_mapper")

# ATT&CK Navigator layer schema version
LAYER_VERSION = "4.5"
NAV_VERSION = "4.9.1"

# Color mapping for statuses
STATUS_COLORS: dict[Status, str] = {
    Status.VULNERABLE: "#ff6666",     # Red
    Status.NOT_VULNERABLE: "#83d353", # Green
    Status.ERROR: "#ffeb3b",          # Yellow
    Status.SKIPPED: "#d3d3d3",        # Gray
    Status.PARTIAL: "#ffb74d",        # Orange
}

SEVERITY_SCORES: dict[Severity, int] = {
    Severity.CRITICAL: 100,
    Severity.HIGH: 75,
    Severity.MEDIUM: 50,
    Severity.LOW: 25,
    Severity.INFO: 5,
}


class MitreMapper:
    """Maps scan results to ATT&CK Navigator JSON layers."""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_layer(self, scan_result: ScanResult) -> Path:
        """Generate an ATT&CK Navigator JSON layer from scan results."""
        techniques = []

        for result in scan_result.results:
            technique_entry = {
                "techniqueID": result.technique_id,
                "tactic": result.tactic.value.replace("_", "-"),
                "color": STATUS_COLORS.get(result.status, "#ffffff"),
                "comment": self._build_comment(result),
                "enabled": True,
                "showSubtechniques": True,
            }

            if result.is_vulnerable:
                technique_entry["score"] = SEVERITY_SCORES.get(result.max_severity, 50)

            techniques.append(technique_entry)

        layer = {
            "name": f"RHEL Red Team Scan - {scan_result.scan_id}",
            "versions": {
                "attack": "16",
                "navigator": NAV_VERSION,
                "layer": LAYER_VERSION,
            },
            "domain": "enterprise-attack",
            "description": (
                f"Scan results for {scan_result.target_info.get('hostname', 'unknown')} "
                f"({scan_result.total_checks} checks, "
                f"{scan_result.vulnerable_count} vulnerable)"
            ),
            "filters": {
                "platforms": ["Linux"],
            },
            "sorting": 3,
            "layout": {
                "layout": "side",
                "showID": True,
                "showName": True,
                "showAggregateScores": True,
                "countUnscored": False,
                "aggregateFunction": "max",
            },
            "hideDisabled": False,
            "techniques": techniques,
            "gradient": {
                "colors": ["#83d353", "#ffeb3b", "#ff6666"],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [
                {"label": "Vulnerable", "color": "#ff6666"},
                {"label": "Secure", "color": "#83d353"},
                {"label": "Error", "color": "#ffeb3b"},
                {"label": "Skipped", "color": "#d3d3d3"},
                {"label": "Partial", "color": "#ffb74d"},
            ],
            "metadata": [
                {"name": "scan_id", "value": scan_result.scan_id},
                {"name": "start_time", "value": scan_result.start_time.isoformat()},
            ],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": False,
            "selectSubtechniquesWithParent": False,
            "selectVisibleTechniques": False,
        }

        path = self.output_dir / f"attack_layer_{scan_result.scan_id}.json"
        path.write_text(json.dumps(layer, indent=2), encoding="utf-8")
        log.info("navigator_layer_generated", path=str(path))
        return path

    def _build_comment(self, result) -> str:
        """Build a comment string for a technique entry."""
        parts = [f"Status: {result.status.value}"]
        if result.finding_count > 0:
            parts.append(f"Findings: {result.finding_count}")
        if result.error_message:
            parts.append(f"Error: {result.error_message}")
        for f in result.findings:
            parts.append(f"- [{f.severity.value}] {f.title}")
        return "\n".join(parts)
