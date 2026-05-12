"""
Tests for Configuration Manager
"""

import tempfile
import os
from pathlib import Path

import pytest
import yaml

from aetherrecon.core.config import AetherConfig, DEFAULTS


class TestAetherConfig:

    def test_defaults_when_no_file(self):
        config = AetherConfig("nonexistent_config_file.yaml")
        assert config.data["general"]["output_dir"] == "./output"
        assert config.data["scope"]["require_confirmation"] is True

    def test_load_yaml(self, tmp_path):
        cfg_data = {
            "general": {"project_name": "Test Project"},
            "rate_limiting": {"requests_per_second": 5},
        }
        cfg_file = tmp_path / "test_config.yaml"
        with open(cfg_file, "w") as f:
            yaml.dump(cfg_data, f)

        config = AetherConfig(cfg_file)
        assert config.data["general"]["project_name"] == "Test Project"
        assert config.data["rate_limiting"]["requests_per_second"] == 5
        # Defaults should still be present
        assert "scope" in config.data

    def test_profile_retrieval(self):
        config = AetherConfig("nonexistent.yaml")
        profile = config.get_profile("safe")
        assert "modules" in profile
        assert profile["rate_limit"] == 5

    def test_unknown_profile_fallback(self):
        config = AetherConfig("nonexistent.yaml")
        profile = config.get_profile("nonexistent_profile")
        assert "modules" in profile  # Falls back to standard

    def test_module_config(self):
        config = AetherConfig("nonexistent.yaml")
        port_cfg = config.get_module_config("port_scan")
        assert port_cfg["scan_type"] == "connect"
        assert port_cfg["timeout"] == 2

    def test_rate_limit(self):
        config = AetherConfig("nonexistent.yaml")
        assert config.get_rate_limit("safe") == 5
        assert config.get_rate_limit("ctf") == 50
        assert config.get_rate_limit() == 10  # Global default
