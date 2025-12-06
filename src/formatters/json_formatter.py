"""JSON Report Formatter"""

import json
from typing import Dict, Any
from pathlib import Path
from datetime import datetime


class JSONFormatter:
    """Formats scan results as JSON"""

    def format(self, report_data: Dict[str, Any], output_path: str) -> str:
        """
        Format report as JSON

        Args:
            report_data: Aggregated report data
            output_path: Path to write JSON file

        Returns:
            Path to generated file
        """
        # Generate timestamp in yyyy-mm-dd-hh-mm format
        timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M")
        output_file = Path(output_path) / f"{timestamp}-scan-report.json"

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)

        return str(output_file)
