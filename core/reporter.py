"""Report generation for RHEL Red Teaming tool."""

from __future__ import annotations

import csv
import json
from datetime import datetime
from io import StringIO
from pathlib import Path

import structlog
from jinja2 import Environment, FileSystemLoader

from core.models import ScanResult, Status

log = structlog.get_logger("reporter")


class Reporter:
    """Generates scan reports in multiple formats."""

    def __init__(self, output_dir: str = "reports", template_dir: str = "templates"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.template_dir = Path(template_dir)

    def generate(self, scan_result: ScanResult, fmt: str = "json") -> Path:
        """Generate a report in the specified format."""
        match fmt:
            case "json":
                return self._generate_json(scan_result)
            case "csv":
                return self._generate_csv(scan_result)
            case "html":
                return self._generate_html(scan_result)
            case _:
                raise ValueError(f"Unsupported format: {fmt}")

    def _output_path(self, scan_result: ScanResult, ext: str) -> Path:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        return self.output_dir / f"scan_{scan_result.scan_id}_{timestamp}.{ext}"

    def _generate_json(self, scan_result: ScanResult) -> Path:
        """Generate JSON report."""
        path = self._output_path(scan_result, "json")
        data = scan_result.to_dict()
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        log.info("report_generated", format="json", path=str(path))
        return path

    def _generate_csv(self, scan_result: ScanResult) -> Path:
        """Generate CSV report."""
        path = self._output_path(scan_result, "csv")
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Technique ID",
            "Technique Name",
            "Tactic",
            "Status",
            "Severity",
            "Findings",
            "Duration (s)",
            "Error",
        ])
        for r in scan_result.results:
            writer.writerow([
                r.technique_id,
                r.technique_name,
                r.tactic.value,
                r.status.value,
                r.max_severity.value,
                r.finding_count,
                f"{r.duration_seconds:.2f}",
                r.error_message,
            ])
        path.write_text(output.getvalue(), encoding="utf-8")
        log.info("report_generated", format="csv", path=str(path))
        return path

    def _generate_html(self, scan_result: ScanResult) -> Path:
        """Generate HTML report using Jinja2 template."""
        path = self._output_path(scan_result, "html")

        if not self.template_dir.exists():
            log.warning("template_dir_missing", path=str(self.template_dir))
            return self._generate_json(scan_result)

        env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=True,
        )

        try:
            template = env.get_template("report.html")
        except Exception:
            log.warning("template_not_found", template="report.html")
            return self._generate_json(scan_result)

        # Build summary stats
        total = scan_result.total_checks
        vuln = scan_result.vulnerable_count
        secure = sum(1 for r in scan_result.results if r.status == Status.NOT_VULNERABLE)
        errors = sum(1 for r in scan_result.results if r.status == Status.ERROR)
        skipped = sum(1 for r in scan_result.results if r.status == Status.SKIPPED)

        # Group results by tactic
        by_tactic: dict[str, list] = {}
        for r in scan_result.results:
            tactic_name = r.tactic.value.replace("_", " ").title()
            by_tactic.setdefault(tactic_name, []).append(r)

        html = template.render(
            scan=scan_result,
            summary={
                "total": total,
                "vulnerable": vuln,
                "secure": secure,
                "errors": errors,
                "skipped": skipped,
            },
            by_tactic=by_tactic,
            generated_at=datetime.now().isoformat(),
        )

        path.write_text(html, encoding="utf-8")
        log.info("report_generated", format="html", path=str(path))
        return path
