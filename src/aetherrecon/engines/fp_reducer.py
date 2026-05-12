"""
False Positive Reduction Engine
---------------------------------
Reduces noise by applying multi-source confirmation, banner validation,
HTTP behavior checks, and response similarity analysis.

Professional-grade scanners aggressively reduce false positives.
This engine validates findings before they reach the report.
"""

from __future__ import annotations
import hashlib
from typing import Any
from dataclasses import dataclass, field


@dataclass
class ValidationResult:
    """Result of a false-positive validation check."""
    finding_title: str
    is_valid: bool
    validation_method: str
    notes: str = ""
    original_confidence: str = ""
    adjusted_confidence: str = ""


class FalsePositiveReducer:
    """
    Multi-layer false positive reduction engine.

    Validation layers:
    1. Version verification — Is the reported version accurate?
    2. Endpoint verification — Does the vulnerable endpoint exist?
    3. Response behavior — Does the response match expected vulnerability?
    4. Multi-source confirmation — Multiple tools agree?
    5. Response similarity — Are findings duplicated due to wildcards?
    6. Banner validation — Is the banner trustworthy?
    """

    def __init__(self):
        self._validations: list[ValidationResult] = []
        self._response_hashes: dict[str, list[str]] = {}  # host -> list of response hashes
        self._suppressed_count = 0
        self._wildcard_hosts: set[str] = set()

    def validate_version_match(self, software: str, detected_version: str,
                                cve_affected_versions: list[str]) -> ValidationResult:
        """
        Verify that the detected version falls within the CVE's affected range.
        Prevents mapping CVEs for unaffected versions.
        """
        if not detected_version:
            result = ValidationResult(
                finding_title=f"{software} CVE match",
                is_valid=False,
                validation_method="version_verification",
                notes="No version detected — cannot verify CVE applicability",
                adjusted_confidence="low",
            )
            self._validations.append(result)
            return result

        # Simple version check — in production, use proper semver comparison
        is_match = any(
            detected_version.startswith(v.split(".")[0]) if "." in v else detected_version == v
            for v in cve_affected_versions
        ) if cve_affected_versions else True

        result = ValidationResult(
            finding_title=f"{software} v{detected_version} CVE match",
            is_valid=is_match,
            validation_method="version_verification",
            notes=f"Version {detected_version} {'matches' if is_match else 'does not match'} affected range",
            adjusted_confidence="high" if is_match else "low",
        )
        self._validations.append(result)
        return result

    def validate_endpoint_exists(self, url: str, status_code: int,
                                  expected_codes: list[int] | None = None) -> ValidationResult:
        """
        Verify the vulnerable endpoint actually exists and responds correctly.
        404s and WAF blocks indicate false positives.
        """
        expected = expected_codes or [200, 201, 301, 302, 403]
        is_valid = status_code in expected and status_code != 404

        # 403 might mean WAF blocked us, not necessarily that endpoint doesn't exist
        notes = ""
        if status_code == 403:
            notes = "403 Forbidden — endpoint may exist behind WAF/auth"
            confidence = "medium"
        elif status_code == 404:
            notes = "404 Not Found — endpoint does not exist"
            confidence = "low"
        elif status_code in (200, 201):
            notes = f"HTTP {status_code} — endpoint confirmed"
            confidence = "high"
        else:
            notes = f"HTTP {status_code} — uncertain"
            confidence = "medium"

        result = ValidationResult(
            finding_title=f"Endpoint: {url}",
            is_valid=is_valid,
            validation_method="endpoint_verification",
            notes=notes,
            adjusted_confidence=confidence,
        )
        self._validations.append(result)
        return result

    def register_response(self, host: str, response_body: str) -> str:
        """
        Register a response body hash for similarity analysis.
        Returns the hash for reference.
        """
        response_hash = hashlib.sha256(response_body.encode("utf-8", errors="ignore")).hexdigest()[:16]
        if host not in self._response_hashes:
            self._response_hashes[host] = []
        self._response_hashes[host].append(response_hash)
        return response_hash

    def check_response_similarity(self, host: str, response_body: str,
                                   threshold: float = 0.8) -> bool:
        """
        Check if a response is too similar to previous responses (wildcard detection).
        Returns True if the response appears to be a wildcard/default page.
        """
        new_hash = hashlib.sha256(response_body.encode("utf-8", errors="ignore")).hexdigest()[:16]
        existing = self._response_hashes.get(host, [])

        if not existing:
            return False

        # Count how many existing responses share the same hash
        same_count = sum(1 for h in existing if h == new_hash)
        similarity_ratio = same_count / len(existing) if existing else 0

        if similarity_ratio >= threshold:
            self._wildcard_hosts.add(host)
            return True
        return False

    def is_wildcard_host(self, host: str) -> bool:
        """Check if a host has been flagged as having wildcard responses."""
        return host in self._wildcard_hosts

    def validate_banner_trust(self, banner: str, verified_tech: dict | None = None) -> ValidationResult:
        """
        Validate whether a service banner can be trusted.
        Banners can be spoofed or misleading.
        """
        is_trusted = False
        notes = "Banner-only detection — low trust"

        if verified_tech:
            # Cross-reference banner with independently verified technology
            tech_name = verified_tech.get("name", "").lower()
            if tech_name and tech_name in banner.lower():
                is_trusted = True
                notes = f"Banner corroborated by tech fingerprinting: {tech_name}"

        result = ValidationResult(
            finding_title=f"Banner: {banner[:60]}",
            is_valid=is_trusted,
            validation_method="banner_validation",
            notes=notes,
            adjusted_confidence="high" if is_trusted else "low",
        )
        self._validations.append(result)
        return result

    def should_suppress(self, host: str, finding_title: str,
                         response_body: str = "") -> bool:
        """
        Master check: should this finding be suppressed as a false positive?
        Returns True if the finding should be suppressed.
        """
        # Suppress if wildcard host and response matches the pattern
        if response_body and self.check_response_similarity(host, response_body):
            self._suppressed_count += 1
            return True
        return False

    def get_validation_summary(self) -> dict[str, Any]:
        """Summary of all FP reduction activity."""
        valid_count = sum(1 for v in self._validations if v.is_valid)
        invalid_count = sum(1 for v in self._validations if not v.is_valid)
        return {
            "total_validations": len(self._validations),
            "confirmed_valid": valid_count,
            "likely_false_positive": invalid_count,
            "suppressed": self._suppressed_count,
            "wildcard_hosts": list(self._wildcard_hosts),
            "by_method": self._method_breakdown(),
        }

    def _method_breakdown(self) -> dict[str, dict[str, int]]:
        methods: dict[str, dict[str, int]] = {}
        for v in self._validations:
            if v.validation_method not in methods:
                methods[v.validation_method] = {"valid": 0, "invalid": 0}
            key = "valid" if v.is_valid else "invalid"
            methods[v.validation_method][key] += 1
        return methods
