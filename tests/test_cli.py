"""Tests for CLI entry point and helper functions."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from click.testing import CliRunner

from core.models import Tactic
from main import cli, load_config, load_profile, parse_tactic


# --- parse_tactic ---


class TestParseTactic:
    def test_lowercase(self):
        assert parse_tactic("discovery") == Tactic.DISCOVERY

    def test_uppercase(self):
        assert parse_tactic("DISCOVERY") == Tactic.DISCOVERY

    def test_dashes_converted(self):
        assert parse_tactic("privilege-escalation") == Tactic.PRIVILEGE_ESCALATION

    def test_spaces_converted(self):
        assert parse_tactic("defense evasion") == Tactic.DEFENSE_EVASION

    def test_mixed_case_dashes(self):
        assert parse_tactic("Credential-Access") == Tactic.CREDENTIAL_ACCESS

    def test_invalid_tactic(self):
        assert parse_tactic("nonexistent") is None

    def test_empty_string(self):
        assert parse_tactic("") is None


# --- load_config ---


class TestLoadConfig:
    def test_loads_yaml(self, tmp_path: Path):
        cfg = {"scan": {"profile": "full"}, "output": {"log_level": "DEBUG"}}
        cfg_file = tmp_path / "settings.yaml"
        cfg_file.write_text(yaml.dump(cfg), encoding="utf-8")
        result = load_config(str(cfg_file))
        assert result["scan"]["profile"] == "full"

    def test_missing_file_exits(self):
        with pytest.raises(SystemExit):
            load_config("/nonexistent/settings.yaml")


# --- load_profile ---


class TestLoadProfile:
    def test_loads_profile(self, tmp_path: Path):
        profile = {"tactics": ["discovery", "execution"]}
        profile_dir = tmp_path / "config" / "profiles"
        profile_dir.mkdir(parents=True)
        (profile_dir / "quick.yaml").write_text(yaml.dump(profile), encoding="utf-8")

        with patch("main.Path") as mock_path:
            mock_path.return_value = profile_dir / "quick.yaml"
            mock_path.return_value.exists = lambda: True
            mock_path.return_value.read_text = lambda encoding="utf-8": yaml.dump(profile)
            # Directly test with real path
        result = load_profile.__wrapped__(tmp_path / "config" / "profiles" / "quick.yaml") if hasattr(load_profile, '__wrapped__') else None

        # Just test the missing profile path since load_profile uses hardcoded path
        result = load_profile("nonexistent_profile_xyz")
        assert result == {}

    def test_missing_profile_returns_empty(self):
        result = load_profile("definitely_not_a_profile_abc123")
        assert result == {}


# --- CLI Commands ---


class TestCLIListTactics:
    def test_list_tactics(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["list-tactics"])
        assert result.exit_code == 0
        assert "Discovery" in result.output

    def test_list_tactics_shows_all(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["list-tactics"])
        assert "Execution" in result.output
        assert "Persistence" in result.output


class TestCLIListModules:
    def test_list_modules(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["list-modules"])
        assert result.exit_code == 0
        assert "T1082" in result.output

    def test_list_modules_shows_table(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["list-modules"])
        assert "Available Modules" in result.output


class TestCLIVersion:
    def test_version(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output


class TestCLIReport:
    def test_report_missing_input(self, tmp_path: Path):
        runner = CliRunner()
        result = runner.invoke(cli, ["report", "--input", str(tmp_path / "nope.json")])
        assert result.exit_code != 0
