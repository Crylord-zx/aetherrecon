"""
JSON Reporter
--------------
Exports scan results to a structured JSON file.
"""

import json
from pathlib import Path
from typing import Any


class JSONReporter:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir

    async def generate(self, metadata: dict, results: dict[str, Any]) -> Path:
        report = {
            "metadata": metadata,
            "results": results,
        }

        filename = f"aetherrecon_report_{metadata.get('target', 'unknown')}.json"
        filepath = self.output_dir / filename

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)

        return filepath
