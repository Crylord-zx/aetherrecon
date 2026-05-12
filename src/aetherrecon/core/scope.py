"""
Scope Validator
---------------
Ensures targets are authorized before scanning. Implements blocklist matching
with glob patterns and explicit allowlist checking.
"""

import fnmatch
import ipaddress
import re
from typing import Any

import tldextract

from aetherrecon.core.config import AetherConfig


class ScopeValidator:
    """
    Validates whether a target is within the allowed scanning scope.

    Rules (evaluated in order):
    1. Target must NOT match any blocked pattern.
    2. If an allowlist is defined and non-empty, target MUST match at least one entry.
    3. Private/reserved IP ranges are allowed (for lab environments).
    """

    def __init__(self, config: AetherConfig):
        scope_cfg = config.data.get("scope", {})
        self.blocked: list[str] = scope_cfg.get("blocked_targets", [])
        self.allowed: list[str] = scope_cfg.get("allowed_targets", [])
        self.require_confirmation: bool = scope_cfg.get("require_confirmation", True)

    def validate(self, target: str) -> tuple[bool, str]:
        """
        Check if a target is within scope.

        Returns:
            (is_allowed, reason) — True if scanning is permitted, with explanation.
        """
        target = target.strip().lower()

        if not target:
            return False, "Empty target provided."

        # ── Check blocklist ───────────────────────────────────────────────
        for pattern in self.blocked:
            pattern = pattern.strip().lower()
            if fnmatch.fnmatch(target, pattern):
                return False, f"Target matches blocked pattern: '{pattern}'"

            # Also check against the extracted domain
            ext = tldextract.extract(target)
            fqdn = ext.fqdn
            if fqdn and fnmatch.fnmatch(fqdn, pattern):
                return False, f"Domain '{fqdn}' matches blocked pattern: '{pattern}'"

        # ── Check if it's a private/reserved IP (labs, CTFs) ──────────────
        try:
            ip = ipaddress.ip_address(target)
            if ip.is_private or ip.is_reserved:
                return True, "Private/reserved IP range (lab environment assumed)."
        except ValueError:
            pass  # Not an IP, continue

        # ── Check allowlist (if defined) ──────────────────────────────────
        if self.allowed:
            for pattern in self.allowed:
                pattern = pattern.strip().lower()
                if fnmatch.fnmatch(target, pattern):
                    return True, f"Target matches allowed pattern: '{pattern}'"

                ext = tldextract.extract(target)
                fqdn = ext.fqdn
                if fqdn and fnmatch.fnmatch(fqdn, pattern):
                    return True, f"Domain matches allowed pattern: '{pattern}'"

            return False, (
                "Target is not in the allowlist. "
                "Add it to 'scope.allowed_targets' in config.yaml."
            )

        # ── No allowlist defined — allow with confirmation ────────────────
        return True, "No allowlist defined. Authorization will be confirmed interactively."

    def is_ip(self, target: str) -> bool:
        """Check if target is a valid IP address."""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    def is_private_ip(self, target: str) -> bool:
        """Check if target is a private/reserved IP (lab/CTF environment)."""
        try:
            ip = ipaddress.ip_address(target)
            return ip.is_private or ip.is_reserved
        except ValueError:
            return False
