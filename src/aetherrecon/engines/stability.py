"""
Service Stability Protection
-------------------------------
Enterprise scanners avoid breaking services. This module provides
fragile service detection, timeout learning, and safe mode fallback.
"""

from __future__ import annotations
import asyncio
import time
from typing import Any


class ServiceStabilityGuard:
    """
    Monitors service health during scanning and automatically
    switches to safe mode when instability is detected.
    """

    def __init__(self, error_threshold: int = 5, latency_threshold: float = 5.0):
        self.error_threshold = error_threshold
        self.latency_threshold = latency_threshold
        self._host_errors: dict[str, int] = {}
        self._host_latencies: dict[str, list[float]] = {}
        self._fragile_hosts: set[str] = set()
        self._safe_mode_active: bool = False
        self._disabled_modules: set[str] = set()

    def record_response(self, host: str, status_code: int, latency: float):
        """Record a response from a host for stability tracking."""
        # Track latency
        if host not in self._host_latencies:
            self._host_latencies[host] = []
        self._host_latencies[host].append(latency)
        # Keep last 20 measurements
        self._host_latencies[host] = self._host_latencies[host][-20:]

        # Track errors
        if status_code in (429, 503, 502, 504, 0):
            self._host_errors[host] = self._host_errors.get(host, 0) + 1
            if self._host_errors[host] >= self.error_threshold:
                self._fragile_hosts.add(host)
        elif status_code < 400:
            # Reduce error count on success
            if host in self._host_errors:
                self._host_errors[host] = max(0, self._host_errors[host] - 1)

    def is_fragile(self, host: str) -> bool:
        """Check if a host has been flagged as fragile."""
        if host in self._fragile_hosts:
            return True
        avg_latency = self._get_avg_latency(host)
        return avg_latency > self.latency_threshold if avg_latency else False

    def should_use_safe_mode(self, host: str) -> bool:
        """Check if safe mode should be used for a host."""
        return self._safe_mode_active or self.is_fragile(host)

    def get_recommended_delay(self, host: str) -> float:
        """Get recommended delay between requests for a host."""
        if self.is_fragile(host):
            return 3.0
        errors = self._host_errors.get(host, 0)
        if errors > 3:
            return 2.0
        avg_latency = self._get_avg_latency(host)
        if avg_latency and avg_latency > 2.0:
            return 1.5
        return 0.5

    def get_disabled_modules(self) -> set[str]:
        """Get modules that should be disabled for stability."""
        if self._safe_mode_active:
            return {"feroxbuster", "sqlmap", "dalfox", "commix"}
        return self._disabled_modules

    def activate_safe_mode(self):
        """Activate global safe mode."""
        self._safe_mode_active = True
        self._disabled_modules = {"feroxbuster", "sqlmap", "dalfox", "commix"}

    def _get_avg_latency(self, host: str) -> float | None:
        latencies = self._host_latencies.get(host, [])
        return sum(latencies) / len(latencies) if latencies else None

    def get_status(self) -> dict[str, Any]:
        return {
            "safe_mode_active": self._safe_mode_active,
            "fragile_hosts": list(self._fragile_hosts),
            "disabled_modules": list(self._disabled_modules),
            "host_errors": dict(self._host_errors),
        }
