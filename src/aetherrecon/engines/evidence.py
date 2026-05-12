"""
Evidence Preservation Engine
------------------------------
Stores and manages evidence artifacts for findings verification:
screenshots, headers, response snippets, certificates, and fingerprints.
"""

from __future__ import annotations
import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any


@dataclass
class EvidenceItem:
    """A single piece of evidence supporting a finding."""
    evidence_type: str   # screenshot | header | response | certificate | fingerprint | config
    source_module: str
    host: str
    description: str
    data: dict[str, Any] = field(default_factory=dict)
    file_path: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    checksum: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.evidence_type,
            "module": self.source_module,
            "host": self.host,
            "description": self.description,
            "data": self.data,
            "file_path": self.file_path,
            "timestamp": self.timestamp,
            "checksum": self.checksum,
        }


class EvidenceCollector:
    """
    Central evidence collection and storage manager.
    
    Preserves:
    - Screenshots of web interfaces
    - HTTP response headers
    - Response body snippets
    - TLS certificate details
    - Technology fingerprint data
    - Configuration exposures
    """

    def __init__(self, output_dir: str | Path):
        self.output_dir = Path(output_dir)
        self.evidence_dir = self.output_dir / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self._items: list[EvidenceItem] = []

    def add_screenshot(self, host: str, file_path: str, module: str = "",
                       description: str = "") -> EvidenceItem:
        """Record a screenshot as evidence."""
        item = EvidenceItem(
            evidence_type="screenshot",
            source_module=module,
            host=host,
            description=description or f"Screenshot of {host}",
            file_path=file_path,
        )
        self._items.append(item)
        return item

    def add_headers(self, host: str, headers: dict[str, str], url: str = "",
                    module: str = "") -> EvidenceItem:
        """Record HTTP response headers as evidence."""
        item = EvidenceItem(
            evidence_type="header",
            source_module=module,
            host=host,
            description=f"HTTP headers from {url or host}",
            data={"url": url, "headers": headers},
        )
        self._items.append(item)
        return item

    def add_response(self, host: str, url: str, status_code: int,
                     body_snippet: str = "", headers: dict | None = None,
                     module: str = "") -> EvidenceItem:
        """Record an HTTP response as evidence."""
        item = EvidenceItem(
            evidence_type="response",
            source_module=module,
            host=host,
            description=f"HTTP {status_code} response from {url}",
            data={
                "url": url,
                "status_code": status_code,
                "body_snippet": body_snippet[:2000],  # Cap at 2KB
                "headers": headers or {},
            },
        )
        self._items.append(item)
        return item

    def add_certificate(self, host: str, cert_data: dict[str, Any],
                        module: str = "") -> EvidenceItem:
        """Record TLS certificate details as evidence."""
        item = EvidenceItem(
            evidence_type="certificate",
            source_module=module,
            host=host,
            description=f"TLS certificate for {host}",
            data=cert_data,
        )
        self._items.append(item)
        return item

    def add_fingerprint(self, host: str, tech_name: str, version: str = "",
                        match_details: dict | None = None,
                        module: str = "") -> EvidenceItem:
        """Record a technology fingerprint as evidence."""
        item = EvidenceItem(
            evidence_type="fingerprint",
            source_module=module,
            host=host,
            description=f"Technology fingerprint: {tech_name} {version}".strip(),
            data={
                "technology": tech_name,
                "version": version,
                "match_details": match_details or {},
            },
        )
        self._items.append(item)
        return item

    def add_config_exposure(self, host: str, config_type: str,
                            content: str = "", url: str = "",
                            module: str = "") -> EvidenceItem:
        """Record an exposed configuration file as evidence."""
        item = EvidenceItem(
            evidence_type="config",
            source_module=module,
            host=host,
            description=f"Exposed {config_type} on {host}",
            data={
                "config_type": config_type,
                "url": url,
                "content_snippet": content[:2000],
            },
        )
        self._items.append(item)
        return item

    def add_secret(self, host: str, secret_type: str, location: str = "",
                   masked_value: str = "", module: str = "") -> EvidenceItem:
        """Record a discovered secret as evidence."""
        item = EvidenceItem(
            evidence_type="secret",
            source_module=module,
            host=host,
            description=f"Exposed {secret_type} found on {host}",
            data={
                "secret_type": secret_type,
                "location": location,
                "masked_value": masked_value,
            },
        )
        self._items.append(item)
        return item

    def get_evidence(self, host: str | None = None,
                     evidence_type: str | None = None) -> list[EvidenceItem]:
        """Retrieve evidence, optionally filtered by host and/or type."""
        items = self._items
        if host:
            items = [i for i in items if i.host == host]
        if evidence_type:
            items = [i for i in items if i.evidence_type == evidence_type]
        return items

    def save_to_disk(self) -> Path:
        """Persist all evidence items to a JSON file."""
        output = {
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "total_items": len(self._items),
            "items": [item.to_dict() for item in self._items],
        }
        out_file = self.evidence_dir / "evidence_collection.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, default=str)
        return out_file

    def save_raw_content(self, filename: str, content: str | bytes) -> Path:
        """Save raw evidence content (response bodies, configs, etc.)."""
        filepath = self.evidence_dir / filename
        mode = "wb" if isinstance(content, bytes) else "w"
        encoding = None if isinstance(content, bytes) else "utf-8"
        with open(filepath, mode, encoding=encoding) as f:
            f.write(content)
        return filepath

    def get_summary(self) -> dict[str, Any]:
        """Generate an evidence collection summary."""
        type_counts: dict[str, int] = {}
        for item in self._items:
            type_counts[item.evidence_type] = type_counts.get(item.evidence_type, 0) + 1
        return {
            "total": len(self._items),
            "by_type": type_counts,
            "hosts_covered": len(set(i.host for i in self._items)),
        }
