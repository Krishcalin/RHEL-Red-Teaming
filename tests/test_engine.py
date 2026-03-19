"""Tests for the core scan engine."""

from __future__ import annotations

from core.engine import ScanEngine
from core.models import ScanConfig, Tactic


def test_engine_init():
    """Engine should initialize with empty module list when no modules exist."""
    config = ScanConfig()
    engine = ScanEngine(config)
    assert isinstance(engine.modules, list)


def test_engine_filter_by_tactic():
    """Engine should filter modules by tactic."""
    config = ScanConfig(tactics=[Tactic.DISCOVERY])
    engine = ScanEngine(config)
    filtered = engine._filter_modules()
    for m in filtered:
        assert m.TACTIC == Tactic.DISCOVERY


def test_engine_filter_by_technique():
    """Engine should filter modules by technique ID."""
    config = ScanConfig(techniques=["T1082"])
    engine = ScanEngine(config)
    filtered = engine._filter_modules()
    for m in filtered:
        assert m.TECHNIQUE_ID == "T1082"
