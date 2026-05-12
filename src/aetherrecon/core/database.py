"""
Database Layer v2.0
--------------------
Async SQLite database for persisting scan results, findings, and metadata.
Extended with confidence scoring, evidence preservation, risk data,
and asset relationships.
"""

import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

import aiosqlite


class Database:
    """
    Enterprise-grade async SQLite storage for AetherRecon.
    
    Extended Tables:
    - scans, findings, assets (legacy)
    - subdomains, live_hosts, technologies, vulnerabilities
    - screenshots, reports
    - evidence, risk_scores, correlations, secrets
    """

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        self.conn: aiosqlite.Connection | None = None

    async def initialize(self):
        """Create database and tables if they don't exist."""
        self.conn = await aiosqlite.connect(self.db_path)
        await self.conn.execute("PRAGMA journal_mode=WAL")
        await self.conn.execute("PRAGMA foreign_keys=ON")

        await self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                added_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                profile TEXT NOT NULL,
                modules TEXT,
                status TEXT DEFAULT 'running',
                started_at TEXT NOT NULL,
                finished_at TEXT,
                metadata TEXT
            );

            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                subdomain TEXT NOT NULL,
                ip_address TEXT,
                source TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS live_hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                host TEXT NOT NULL,
                port INTEGER,
                scheme TEXT,
                status_code INTEGER,
                title TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS technologies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                host TEXT NOT NULL,
                tech_name TEXT NOT NULL,
                version TEXT,
                category TEXT,
                confidence TEXT DEFAULT 'medium',
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                host TEXT NOT NULL,
                vuln_name TEXT NOT NULL,
                severity TEXT,
                cve_id TEXT,
                description TEXT,
                proof TEXT,
                confidence TEXT DEFAULT 'medium',
                epss_score REAL DEFAULT 0.0,
                exploit_maturity TEXT DEFAULT 'unknown',
                remediation TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS screenshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                host TEXT NOT NULL,
                file_path TEXT NOT NULL,
                classification TEXT DEFAULT 'unknown',
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                report_type TEXT,
                file_path TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                evidence_type TEXT NOT NULL,
                host TEXT,
                module TEXT,
                description TEXT,
                data TEXT,
                file_path TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS risk_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                host TEXT NOT NULL,
                finding_title TEXT,
                composite_score REAL,
                severity TEXT,
                confidence TEXT,
                exposure TEXT,
                exploit_maturity TEXT,
                remediation_priority TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                host TEXT NOT NULL,
                secret_type TEXT,
                location TEXT,
                severity TEXT DEFAULT 'critical',
                masked_value TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS correlations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                rule_name TEXT,
                findings_count INTEGER,
                data TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            -- Legacy tables for backwards compatibility
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                module TEXT NOT NULL,
                category TEXT,
                severity TEXT DEFAULT 'info',
                title TEXT NOT NULL,
                description TEXT,
                data TEXT,
                confidence TEXT DEFAULT 'medium',
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                asset_type TEXT NOT NULL,
                value TEXT NOT NULL,
                metadata TEXT,
                discovered_by TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_assets_scan ON assets(scan_id);
            CREATE INDEX IF NOT EXISTS idx_subdomains_scan ON subdomains(scan_id);
            CREATE INDEX IF NOT EXISTS idx_live_hosts_scan ON live_hosts(scan_id);
            CREATE INDEX IF NOT EXISTS idx_tech_scan ON technologies(scan_id);
            CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id);
            CREATE INDEX IF NOT EXISTS idx_screenshots_scan ON screenshots(scan_id);
            CREATE INDEX IF NOT EXISTS idx_reports_scan ON reports(scan_id);
            CREATE INDEX IF NOT EXISTS idx_evidence_scan ON evidence(scan_id);
            CREATE INDEX IF NOT EXISTS idx_risk_scan ON risk_scores(scan_id);
            CREATE INDEX IF NOT EXISTS idx_secrets_scan ON secrets(scan_id);
            CREATE INDEX IF NOT EXISTS idx_correlations_scan ON correlations(scan_id);
        """)
        
        # Simple migrations
        try:
            await self.conn.execute("ALTER TABLE findings ADD COLUMN confidence TEXT DEFAULT 'medium'")
        except Exception:
            pass # Column already exists
            
        await self.conn.commit()

    async def create_scan(self, target: str, profile: str, modules: list[str]) -> int:
        cursor = await self.conn.execute(
            "INSERT INTO scans (target, profile, modules, started_at) VALUES (?, ?, ?, ?)",
            (target, profile, json.dumps(modules), datetime.now(timezone.utc).isoformat()),
        )
        await self.conn.commit()
        return cursor.lastrowid

    async def finish_scan(self, scan_id: int, status: str = "completed"):
        await self.conn.execute(
            "UPDATE scans SET status = ?, finished_at = ? WHERE id = ?",
            (status, datetime.now(timezone.utc).isoformat(), scan_id),
        )
        await self.conn.commit()

    async def add_finding(self, scan_id: int, module: str, title: str,
                          category: str = "info", severity: str = "info",
                          description: str = "", data: dict | None = None,
                          confidence: str = "medium") -> int:
        cursor = await self.conn.execute(
            """INSERT INTO findings
               (scan_id, module, category, severity, title, description, data, confidence, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, module, category, severity, title, description,
             json.dumps(data or {}), confidence,
             datetime.now(timezone.utc).isoformat()),
        )
        await self.conn.commit()
        return cursor.lastrowid

    async def add_asset(self, scan_id: int, asset_type: str, value: str,
                        discovered_by: str = "", metadata: dict | None = None) -> int:
        cursor = await self.conn.execute(
            """INSERT INTO assets
               (scan_id, asset_type, value, discovered_by, metadata, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (scan_id, asset_type, value, discovered_by,
             json.dumps(metadata or {}),
             datetime.now(timezone.utc).isoformat()),
        )
        await self.conn.commit()
        return cursor.lastrowid

    async def add_subdomain(self, scan_id: int, subdomain: str,
                            ip: str | None = None, source: str = ""):
        await self.conn.execute(
            "INSERT INTO subdomains (scan_id, subdomain, ip_address, source, created_at) VALUES (?, ?, ?, ?, ?)",
            (scan_id, subdomain, ip, source, datetime.now(timezone.utc).isoformat())
        )
        await self.conn.commit()

    async def add_live_host(self, scan_id: int, host: str, port: int,
                            scheme: str, status: int, title: str):
        await self.conn.execute(
            "INSERT INTO live_hosts (scan_id, host, port, scheme, status_code, title, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (scan_id, host, port, scheme, status, title, datetime.now(timezone.utc).isoformat())
        )
        await self.conn.commit()

    async def add_technology(self, scan_id: int, host: str, name: str,
                             version: str = "", category: str = "",
                             confidence: str = "medium"):
        await self.conn.execute(
            "INSERT INTO technologies (scan_id, host, tech_name, version, category, confidence) VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, host, name, version, category, confidence)
        )
        await self.conn.commit()

    async def add_vulnerability(self, scan_id: int, host: str, name: str,
                                severity: str, cve: str = "", desc: str = "",
                                proof: str = "", confidence: str = "medium",
                                epss_score: float = 0.0,
                                exploit_maturity: str = "unknown",
                                remediation: str = ""):
        await self.conn.execute(
            """INSERT INTO vulnerabilities
               (scan_id, host, vuln_name, severity, cve_id, description, proof,
                confidence, epss_score, exploit_maturity, remediation)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, host, name, severity, cve, desc, proof,
             confidence, epss_score, exploit_maturity, remediation)
        )
        await self.conn.commit()

    async def add_screenshot(self, scan_id: int, host: str, file_path: str,
                             classification: str = "unknown"):
        await self.conn.execute(
            "INSERT INTO screenshots (scan_id, host, file_path, classification, created_at) VALUES (?, ?, ?, ?, ?)",
            (scan_id, host, str(file_path), classification,
             datetime.now(timezone.utc).isoformat())
        )
        await self.conn.commit()

    async def add_evidence(self, scan_id: int, evidence_type: str,
                           host: str = "", module: str = "",
                           description: str = "", data: dict | None = None,
                           file_path: str = ""):
        await self.conn.execute(
            """INSERT INTO evidence
               (scan_id, evidence_type, host, module, description, data, file_path, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, evidence_type, host, module, description,
             json.dumps(data or {}), file_path,
             datetime.now(timezone.utc).isoformat())
        )
        await self.conn.commit()

    async def add_secret(self, scan_id: int, host: str, secret_type: str,
                         location: str = "", severity: str = "critical",
                         masked_value: str = ""):
        await self.conn.execute(
            """INSERT INTO secrets
               (scan_id, host, secret_type, location, severity, masked_value, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, host, secret_type, location, severity, masked_value,
             datetime.now(timezone.utc).isoformat())
        )
        await self.conn.commit()

    async def add_risk_score(self, scan_id: int, host: str, finding_title: str,
                             composite_score: float, severity: str = "",
                             confidence: str = "", exposure: str = "",
                             exploit_maturity: str = "",
                             remediation_priority: str = ""):
        await self.conn.execute(
            """INSERT INTO risk_scores
               (scan_id, host, finding_title, composite_score, severity,
                confidence, exposure, exploit_maturity, remediation_priority)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, host, finding_title, composite_score, severity,
             confidence, exposure, exploit_maturity, remediation_priority)
        )
        await self.conn.commit()

    async def get_findings(self, scan_id: int) -> list[dict]:
        async with self.conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY severity, module",
            (scan_id,),
        ) as cursor:
            columns = [desc[0] for desc in cursor.description]
            rows = await cursor.fetchall()
            return [dict(zip(columns, row)) for row in rows]

    async def get_assets(self, scan_id: int) -> list[dict]:
        async with self.conn.execute(
            "SELECT * FROM assets WHERE scan_id = ? ORDER BY asset_type",
            (scan_id,),
        ) as cursor:
            columns = [desc[0] for desc in cursor.description]
            rows = await cursor.fetchall()
            return [dict(zip(columns, row)) for row in rows]

    async def get_vulnerabilities(self, scan_id: int) -> list[dict]:
        async with self.conn.execute(
            "SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY severity",
            (scan_id,),
        ) as cursor:
            columns = [desc[0] for desc in cursor.description]
            rows = await cursor.fetchall()
            return [dict(zip(columns, row)) for row in rows]

    async def get_technologies(self, scan_id: int) -> list[dict]:
        async with self.conn.execute(
            "SELECT * FROM technologies WHERE scan_id = ?",
            (scan_id,),
        ) as cursor:
            columns = [desc[0] for desc in cursor.description]
            rows = await cursor.fetchall()
            return [dict(zip(columns, row)) for row in rows]

    async def close(self):
        if self.conn:
            await self.conn.close()
