"""Entry point for the SECURE-REC desktop application.

    python -m app.main
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:            # also allow `python app/main.py`
    sys.path.insert(0, str(PROJECT_ROOT))


def main() -> None:
    if sys.platform.startswith("win"):
        try:  # crisp text on high-DPI Windows displays
            import ctypes

            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            pass
    from app.gui.app import launch

    launch()


if __name__ == "__main__":
    main()
