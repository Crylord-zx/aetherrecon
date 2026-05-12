"""
Tests for State Manager
"""

import json
from pathlib import Path

import pytest

from aetherrecon.core.state import StateManager


class TestStateManager:

    def test_save_and_load(self, tmp_path):
        state_file = tmp_path / "state.json"
        mgr = StateManager(state_file)
        mgr.set_scan_info("example.com", "safe", ["whois", "dns_enum"])
        mgr.save()

        # Load in new instance
        mgr2 = StateManager(state_file)
        loaded = mgr2.load()
        assert loaded is not None
        assert loaded["target"] == "example.com"
        assert loaded["profile"] == "safe"

    def test_module_complete_tracking(self, tmp_path):
        state_file = tmp_path / "state.json"
        mgr = StateManager(state_file)
        assert not mgr.is_module_complete("whois")

        mgr.mark_module_complete("whois", [{"data": "test"}])
        assert mgr.is_module_complete("whois")
        assert not mgr.is_module_complete("dns_enum")

    def test_clear(self, tmp_path):
        state_file = tmp_path / "state.json"
        mgr = StateManager(state_file)
        mgr.set_scan_info("test.com", "full", ["all"])
        mgr.save()
        assert state_file.exists()

        mgr.clear()
        assert not state_file.exists()

    def test_load_nonexistent(self, tmp_path):
        mgr = StateManager(tmp_path / "does_not_exist.json")
        assert mgr.load() is None
