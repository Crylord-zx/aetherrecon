"""
FastAPI Local API Server
-------------------------
Provides a REST API for programmatic access to AetherRecon.
Runs on localhost only (127.0.0.1) for security.

Endpoints:
    GET  /                    — API info
    GET  /health              — Health check
    POST /scan                — Start a new scan
    GET  /scan/{id}           — Get scan status/results
    GET  /scans               — List all scans
    GET  /profiles            — List scan profiles
    GET  /workflows           — List available workflows
    GET  /tools               — Check external tool status
    GET  /findings/{scan_id}  — Get findings for a scan
"""

import asyncio
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from aetherrecon.core.config import AetherConfig
from aetherrecon.core.database import Database
from aetherrecon.core.scope import ScopeValidator
from aetherrecon.core.scanner import ScanOrchestrator
from aetherrecon.core.state import StateManager
from aetherrecon.core.plugin_manager import PluginManager
from aetherrecon.workflows.engine import WorkflowEngine

# ── Request/Response Models ───────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target: str
    profile: str = "standard"
    modules: list[str] | None = None
    workflow: str | None = None
    confirm_authorized: bool = False

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    target: str
    profile: str
    message: str

class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    target: str
    progress: float
    findings_count: int
    errors: list[str]


# ── App Factory ───────────────────────────────────────────────────────────────

def create_api(config_path: str = "config.yaml") -> FastAPI:
    """Create and configure the FastAPI application."""

    config = AetherConfig(config_path)

    app = FastAPI(
        title="AetherRecon API",
        description="Local API for the AetherRecon reconnaissance framework",
        version="2.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # In-memory scan tracker
    active_scans: dict[str, dict[str, Any]] = {}

    # ── Routes ────────────────────────────────────────────────────────────

    @app.get("/")
    async def root():
        return {
            "name": "AetherRecon API",
            "version": "2.0.0",
            "status": "running",
            "docs": "/docs",
            "warning": "Authorized targets only.",
        }

    @app.get("/health")
    async def health():
        return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}

    @app.get("/profiles")
    async def list_profiles():
        profiles = {}
        for name, prof in config.data.get("profiles", {}).items():
            profiles[name] = {
                "description": prof.get("description", ""),
                "rate_limit": prof.get("rate_limit", 10),
                "threads": prof.get("threads", 10),
                "concurrency": prof.get("concurrency", 30),
                "active_enum": prof.get("active_enum", False),
            }
        return {"profiles": profiles}

    @app.get("/workflows")
    async def list_workflows():
        engine = WorkflowEngine(config)
        return {"workflows": engine.list_workflows()}

    @app.get("/tools")
    async def check_tools():
        pm = PluginManager(config)
        tools = pm.check_tools()
        return {
            "tools": {k: {"available": bool(v), "path": v or ""} for k, v in tools.items()},
            "total_found": sum(1 for v in tools.values() if v),
            "total_checked": len(tools),
        }

    @app.post("/scan", response_model=ScanResponse)
    async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
        # Validate authorization
        if not req.confirm_authorized:
            raise HTTPException(
                status_code=403,
                detail="You must set confirm_authorized=true to certify you have "
                       "written authorization to scan this target.",
            )

        # Validate scope
        scope = ScopeValidator(config)
        allowed, reason = scope.validate(req.target)
        if not allowed:
            raise HTTPException(status_code=403, detail=f"Target blocked: {reason}")

        scan_id = str(uuid.uuid4())[:8]
        active_scans[scan_id] = {
            "status": "queued",
            "target": req.target,
            "profile": req.profile,
            "progress": 0.0,
            "findings_count": 0,
            "errors": [],
        }

        background_tasks.add_task(
            _execute_scan, scan_id, req.target, req.profile,
            req.modules, config, active_scans,
        )

        return ScanResponse(
            scan_id=scan_id,
            status="queued",
            target=req.target,
            profile=req.profile,
            message=f"Scan queued. Monitor at GET /scan/{scan_id}",
        )

    @app.get("/scan/{scan_id}")
    async def get_scan_status(scan_id: str):
        if scan_id not in active_scans:
            raise HTTPException(status_code=404, detail="Scan not found")
        return active_scans[scan_id]

    @app.get("/scans")
    async def list_scans():
        return {"scans": active_scans}

    @app.get("/findings/{scan_id}")
    async def get_findings(scan_id: str):
        output_dir = Path(config.data.get("general", {}).get("output_dir", "./output"))
        db = Database(output_dir / "aetherrecon.db")
        await db.initialize()
        # Try to find scan by matching — simplified lookup
        findings = []
        try:
            async with db.conn.execute(
                "SELECT * FROM findings ORDER BY id DESC LIMIT 100"
            ) as cursor:
                columns = [desc[0] for desc in cursor.description]
                rows = await cursor.fetchall()
                findings = [dict(zip(columns, row)) for row in rows]
        except Exception:
            pass
        await db.close()
        return {"scan_id": scan_id, "findings": findings}

    return app


async def _execute_scan(
    scan_id: str,
    target: str,
    profile: str,
    modules: list[str] | None,
    config: AetherConfig,
    tracker: dict,
):
    """Background task to execute a scan."""
    tracker[scan_id]["status"] = "running"

    output_dir = Path(config.data.get("general", {}).get("output_dir", "./output"))
    output_dir.mkdir(parents=True, exist_ok=True)

    db = Database(output_dir / "aetherrecon.db")
    await db.initialize()

    state_mgr = StateManager(output_dir / ".aetherrecon_state.json")
    plugin_mgr = PluginManager(config)

    profile_cfg = config.get_profile(profile)
    module_list = modules or profile_cfg.get("modules", ["all"])

    from rich.console import Console
    console = Console(quiet=True)

    orchestrator = ScanOrchestrator(
        target=target, profile=profile, modules=module_list,
        config=config, db=db, state_manager=state_mgr,
        plugin_manager=plugin_mgr, console=console,
    )

    try:
        results = await orchestrator.run()

        total_findings = sum(
            len(v) if isinstance(v, list) else 1
            for k, v in results.items() if k not in ("timestamp_start", "errors")
        )

        tracker[scan_id]["status"] = "completed"
        tracker[scan_id]["progress"] = 100.0
        tracker[scan_id]["findings_count"] = total_findings
        tracker[scan_id]["errors"] = results.get("errors", [])
        tracker[scan_id]["results"] = results

    except Exception as e:
        tracker[scan_id]["status"] = "failed"
        tracker[scan_id]["errors"].append(str(e))

    finally:
        await db.close()


def run_api(config_path: str = "config.yaml", host: str = "127.0.0.1", port: int = 8337):
    """Start the API server."""
    import uvicorn
    app = create_api(config_path)
    uvicorn.run(app, host=host, port=port, log_level="info")
