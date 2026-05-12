"""
Tests for Scope Validator
"""

import pytest
from aetherrecon.core.scope import ScopeValidator
from aetherrecon.core.config import AetherConfig


class MockConfig:
    """Mock config for testing."""
    def __init__(self, scope_data: dict):
        self.data = {"scope": scope_data}


class TestScopeValidator:

    def test_blocked_localhost(self):
        config = MockConfig({
            "blocked_targets": ["localhost", "127.0.0.1"],
            "allowed_targets": [],
        })
        validator = ScopeValidator(config)
        allowed, reason = validator.validate("localhost")
        assert not allowed
        assert "blocked" in reason.lower()

    def test_blocked_gov_domain(self):
        config = MockConfig({
            "blocked_targets": ["*.gov"],
            "allowed_targets": [],
        })
        validator = ScopeValidator(config)
        allowed, reason = validator.validate("whitehouse.gov")
        assert not allowed

    def test_private_ip_allowed(self):
        config = MockConfig({
            "blocked_targets": [],
            "allowed_targets": [],
        })
        validator = ScopeValidator(config)
        allowed, reason = validator.validate("192.168.1.1")
        assert allowed
        assert "private" in reason.lower() or "reserved" in reason.lower()

    def test_allowlist_match(self):
        config = MockConfig({
            "blocked_targets": [],
            "allowed_targets": ["*.example.com"],
        })
        validator = ScopeValidator(config)
        allowed, reason = validator.validate("test.example.com")
        assert allowed

    def test_allowlist_no_match(self):
        config = MockConfig({
            "blocked_targets": [],
            "allowed_targets": ["*.example.com"],
        })
        validator = ScopeValidator(config)
        allowed, reason = validator.validate("evil.com")
        assert not allowed
        assert "allowlist" in reason.lower()

    def test_empty_target(self):
        config = MockConfig({
            "blocked_targets": [],
            "allowed_targets": [],
        })
        validator = ScopeValidator(config)
        allowed, reason = validator.validate("")
        assert not allowed

    def test_is_private_ip(self):
        config = MockConfig({"blocked_targets": [], "allowed_targets": []})
        validator = ScopeValidator(config)
        assert validator.is_private_ip("10.0.0.1")
        assert validator.is_private_ip("172.16.0.1")
        assert validator.is_private_ip("192.168.1.1")
        assert not validator.is_private_ip("8.8.8.8")
        assert not validator.is_private_ip("not-an-ip")
