"""Tests for CIS Benchmark and NIST 800-53 compliance mapping."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from core.compliance import (
    CIS_CONTROLS,
    CIS_RHEL_BENCHMARK,
    DISA_STIG_RHEL8,
    DISA_STIG_RHEL9,
    NIST_CONTROLS,
    ComplianceMapper,
    ComplianceRef,
)
from core.models import (
    Finding,
    ModuleResult,
    ScanConfig,
    ScanResult,
    Severity,
    Status,
    Tactic,
)


@pytest.fixture
def mapper() -> ComplianceMapper:
    return ComplianceMapper()


@pytest.fixture
def scan_result() -> ScanResult:
    start = datetime(2026, 3, 20, 10, 0, 0)
    return ScanResult(
        scan_id="comp01",
        config=ScanConfig(),
        start_time=start,
        end_time=start + timedelta(seconds=30),
        target_info={"hostname": "rhel-test"},
        results=[
            ModuleResult(
                technique_id="T1021",
                technique_name="Remote Services",
                tactic=Tactic.LATERAL_MOVEMENT,
                status=Status.VULNERABLE,
                findings=[
                    Finding(
                        title="SSH root login",
                        description="root login enabled",
                        severity=Severity.HIGH,
                    ),
                ],
                mitigations=["Disable root login"],
            ),
            ModuleResult(
                technique_id="T1082",
                technique_name="System Info",
                tactic=Tactic.DISCOVERY,
                status=Status.NOT_VULNERABLE,
            ),
            ModuleResult(
                technique_id="T1059",
                technique_name="Command Scripting",
                tactic=Tactic.EXECUTION,
                status=Status.VULNERABLE,
                findings=[
                    Finding(
                        title="SELinux disabled",
                        description="not enforcing",
                        severity=Severity.HIGH,
                    ),
                ],
            ),
        ],
    )


class TestComplianceRef:
    def test_create_ref(self):
        r = ComplianceRef("CIS Controls v8", "4.1", "Secure Config", "details")
        assert r.framework == "CIS Controls v8"
        assert r.control_id == "4.1"
        assert r.control_name == "Secure Config"
        assert r.description == "details"

    def test_default_description(self):
        r = ComplianceRef("NIST 800-53", "AC-2", "Account Mgmt")
        assert r.description == ""


class TestGetRefs:
    def test_known_technique(self, mapper: ComplianceMapper):
        refs = mapper.get_refs("T1021")
        assert len(refs) > 0
        frameworks = {r.framework for r in refs}
        assert "CIS Controls v8" in frameworks
        assert "NIST 800-53" in frameworks

    def test_known_technique_with_rhel_benchmark(self, mapper: ComplianceMapper):
        refs = mapper.get_refs("T1003")
        frameworks = {r.framework for r in refs}
        assert "CIS RHEL 9 Benchmark" in frameworks

    def test_known_technique_with_disa_stig(self, mapper: ComplianceMapper):
        refs = mapper.get_refs("T1021")
        frameworks = {r.framework for r in refs}
        assert "DISA STIG RHEL 8" in frameworks
        assert "DISA STIG RHEL 9" in frameworks

    def test_disa_stig_refs_have_description(self, mapper: ComplianceMapper):
        refs = mapper.get_refs("T1562")
        stig_refs = [r for r in refs if "DISA STIG" in r.framework]
        assert len(stig_refs) > 0
        for r in stig_refs:
            assert r.description, f"STIG ref {r.control_id} has empty description (STIG ID)"

    def test_subtechnique_maps_to_parent(self, mapper: ComplianceMapper):
        refs = mapper.get_refs("T1021.004")
        parent_refs = mapper.get_refs("T1021")
        assert len(refs) == len(parent_refs)

    def test_unknown_technique(self, mapper: ComplianceMapper):
        refs = mapper.get_refs("T9999")
        assert refs == []


class TestGetRefsByFramework:
    def test_groups_by_framework(self, mapper: ComplianceMapper):
        grouped = mapper.get_refs_by_framework("T1021")
        assert "CIS Controls v8" in grouped
        assert "NIST 800-53" in grouped
        for fw, refs in grouped.items():
            for r in refs:
                assert r.framework == fw

    def test_empty_for_unknown(self, mapper: ComplianceMapper):
        grouped = mapper.get_refs_by_framework("T9999")
        assert grouped == {}


class TestEnrichResult:
    def test_enriches_with_compliance(self, mapper: ComplianceMapper):
        result = ModuleResult(
            technique_id="T1082",
            technique_name="System Info",
            tactic=Tactic.DISCOVERY,
            status=Status.VULNERABLE,
        )
        enriched = mapper.enrich_result(result)
        assert enriched["result"] is result
        assert enriched["has_compliance"] is True
        assert "CIS Controls v8" in enriched["compliance"]

    def test_enriches_unknown_technique(self, mapper: ComplianceMapper):
        result = ModuleResult(
            technique_id="T9999",
            technique_name="Unknown",
            tactic=Tactic.DISCOVERY,
            status=Status.NOT_VULNERABLE,
        )
        enriched = mapper.enrich_result(result)
        assert enriched["has_compliance"] is False
        assert enriched["compliance"] == {}


class TestEnrichScan:
    def test_enriches_all_results(self, mapper: ComplianceMapper, scan_result: ScanResult):
        enriched = mapper.enrich_scan(scan_result)
        assert len(enriched) == 3
        for item in enriched:
            assert "result" in item
            assert "compliance" in item
            assert "has_compliance" in item


class TestComplianceSummary:
    def test_summary_counts(self, mapper: ComplianceMapper, scan_result: ScanResult):
        summary = mapper.get_compliance_summary(scan_result)
        assert len(summary) > 0

        for fw, stats in summary.items():
            assert "total" in stats
            assert "violated" in stats
            assert "compliant" in stats
            assert stats["compliant"] == stats["total"] - stats["violated"]
            assert stats["total"] >= stats["violated"]

    def test_vulnerable_results_map_to_violated(self, mapper: ComplianceMapper):
        sr = ScanResult(
            scan_id="test",
            config=ScanConfig(),
            results=[
                ModuleResult(
                    technique_id="T1021",
                    technique_name="Remote Services",
                    tactic=Tactic.LATERAL_MOVEMENT,
                    status=Status.VULNERABLE,
                ),
            ],
        )
        summary = mapper.get_compliance_summary(sr)
        for fw, stats in summary.items():
            assert stats["violated"] > 0

    def test_not_vulnerable_has_no_violations(self, mapper: ComplianceMapper):
        sr = ScanResult(
            scan_id="test",
            config=ScanConfig(),
            results=[
                ModuleResult(
                    technique_id="T1021",
                    technique_name="Remote Services",
                    tactic=Tactic.LATERAL_MOVEMENT,
                    status=Status.NOT_VULNERABLE,
                ),
            ],
        )
        summary = mapper.get_compliance_summary(sr)
        for fw, stats in summary.items():
            assert stats["violated"] == 0

    def test_empty_scan(self, mapper: ComplianceMapper):
        sr = ScanResult(scan_id="empty", config=ScanConfig())
        summary = mapper.get_compliance_summary(sr)
        assert summary == {}


class TestMappingCoverage:
    """Verify that major techniques have mappings in all frameworks."""

    CORE_TECHNIQUES = ["T1021", "T1003", "T1059", "T1082", "T1046", "T1562", "T1548"]

    def test_cis_controls_coverage(self):
        for tid in self.CORE_TECHNIQUES:
            assert tid in CIS_CONTROLS, f"{tid} missing from CIS Controls"

    def test_nist_controls_coverage(self):
        for tid in self.CORE_TECHNIQUES:
            assert tid in NIST_CONTROLS, f"{tid} missing from NIST 800-53"

    def test_cis_rhel_benchmark_has_entries(self):
        assert len(CIS_RHEL_BENCHMARK) > 0

    def test_disa_stig_rhel8_coverage(self):
        for tid in self.CORE_TECHNIQUES:
            assert tid in DISA_STIG_RHEL8, f"{tid} missing from DISA STIG RHEL 8"

    def test_disa_stig_rhel9_coverage(self):
        for tid in self.CORE_TECHNIQUES:
            assert tid in DISA_STIG_RHEL9, f"{tid} missing from DISA STIG RHEL 9"

    def test_disa_stig_rhel8_has_entries(self):
        assert len(DISA_STIG_RHEL8) >= 25, f"Expected 25+ techniques, got {len(DISA_STIG_RHEL8)}"

    def test_disa_stig_rhel9_has_entries(self):
        assert len(DISA_STIG_RHEL9) >= 25, f"Expected 25+ techniques, got {len(DISA_STIG_RHEL9)}"

    def test_no_empty_refs(self):
        all_maps = [
            ("CIS Controls", CIS_CONTROLS),
            ("NIST 800-53", NIST_CONTROLS),
            ("DISA STIG RHEL 8", DISA_STIG_RHEL8),
            ("DISA STIG RHEL 9", DISA_STIG_RHEL9),
        ]
        for name, mapping in all_maps:
            for tid, refs in mapping.items():
                assert len(refs) > 0, f"{name} {tid} has empty refs"
                for r in refs:
                    assert r.control_id, f"{name} {tid} has empty control_id"
                    assert r.control_name, f"{name} {tid} has empty control_name"

    def test_stig_refs_have_rule_ids(self):
        """DISA STIG refs should have V-XXXXXX format control IDs."""
        for tid, refs in DISA_STIG_RHEL8.items():
            for r in refs:
                assert r.control_id.startswith("V-"), f"STIG RHEL8 {tid} control_id should start with V-: {r.control_id}"

        for tid, refs in DISA_STIG_RHEL9.items():
            for r in refs:
                assert r.control_id.startswith("V-"), f"STIG RHEL9 {tid} control_id should start with V-: {r.control_id}"
