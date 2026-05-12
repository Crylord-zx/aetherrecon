"""
State Manager
-------------
Handles saving and loading scan state for the resume feature.
"""

import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Any


class StateManager:
    def __init__(self, state_path: str | Path):
        self.state_path = Path(state_path)
        self._state: dict[str, Any] = {}

    def load(self) -> dict[str, Any] | None:
        if self.state_path.exists():
            try:
                with open(self.state_path, "r", encoding="utf-8") as f:
                    self._state = json.load(f)
                return self._state
            except (json.JSONDecodeError, OSError):
                return None
        return None

    def save(self):
        self._state["timestamp"] = datetime.now(timezone.utc).isoformat()
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.state_path, "w", encoding="utf-8") as f:
            json.dump(self._state, f, indent=2, default=str)

    def mark_module_complete(self, module_name: str, results: Any = None):
        if "completed_modules" not in self._state:
            self._state["completed_modules"] = {}
        self._state["completed_modules"][module_name] = {
            "status": "complete",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "result_count": len(results) if isinstance(results, (list, dict)) else 0,
        }
        self.save()

    def is_module_complete(self, module_name: str) -> bool:
        completed = self._state.get("completed_modules", {})
        return module_name in completed and completed[module_name].get("status") == "complete"

    def set_scan_info(self, target: str, profile: str, modules: list[str]):
        self._state["target"] = target
        self._state["profile"] = profile
        self._state["modules"] = modules
        self.save()

    def clear(self):
        self._state = {}
        if self.state_path.exists():
            self.state_path.unlink()
