"""Uniform result object returned by every task (and later the pipeline).

The GUI only has to know how to display a ``TaskResult``; it never needs to
understand the cryptography behind it.  Each result can also be written to
disk as a human-readable ``report.txt`` plus a machine-readable
``report.json`` so the evidence can be reused in the final project report.
"""

from __future__ import annotations

import functools
import json
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from core.logging_utils import get_logger

_log = get_logger(__name__)


class Status(str, Enum):
    PASS = "PASS"                      # a verification succeeded
    FAIL = "FAIL"                      # a verification failed
    COMPLETED = "COMPLETED"            # an analysis/measurement finished
    NOT_APPLICABLE = "NOT APPLICABLE"  # input unsuitable (e.g. image required)
    ERROR = "ERROR"                    # unexpected problem while running


@dataclass
class TaskResult:
    task_id: str
    title: str
    status: Status = Status.COMPLETED
    # Short "label: value" lines shown prominently in the GUI results area.
    summary: list[tuple[str, str]] = field(default_factory=list)
    # Longer explanatory text (what was done, why it matters).
    details: str = ""
    # Files produced by the run (encrypted files, charts, CSVs, reports ...).
    artifacts: list[Path] = field(default_factory=list)
    # Structured numbers for tests and report generation.
    data: dict[str, Any] = field(default_factory=dict)
    reason: str = ""  # explanation for NOT_APPLICABLE / ERROR / FAIL
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def add(self, label: str, value: Any) -> None:
        self.summary.append((label, str(value)))

    @property
    def ok(self) -> bool:
        return self.status in (Status.PASS, Status.COMPLETED)

    def to_text(self) -> str:
        lines = [
            f"{self.task_id} - {self.title}",
            f"Status: {self.status.value}",
        ]
        if self.reason:
            lines.append(f"Reason: {self.reason}")
        if self.summary:
            width = max(len(label) for label, _ in self.summary)
            lines.append("")
            lines += [f"{label.ljust(width)} : {value}" for label, value in self.summary]
        if self.details:
            # Strip only blank lines: leading spaces may be table alignment.
            lines += ["", self.details.strip("\n")]
        if self.artifacts:
            lines += ["", "Generated files:"]
            lines += [f"  - {p}" for p in self.artifacts]
        lines += ["", f"Generated (UTC): {self.timestamp}"]
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "title": self.title,
            "status": self.status.value,
            "reason": self.reason,
            "summary": dict(self.summary),
            "data": self.data,
            "artifacts": [str(p) for p in self.artifacts],
            "timestamp": self.timestamp,
        }

    def save(self, out_dir: Path) -> None:
        """Write report.txt / report.json into ``out_dir`` and list them as artifacts."""
        out_dir.mkdir(parents=True, exist_ok=True)
        txt, js = out_dir / "report.txt", out_dir / "report.json"
        for p in (txt, js):
            if p not in self.artifacts:
                self.artifacts.append(p)
        txt.write_text(self.to_text() + "\n", encoding="utf-8")
        js.write_text(json.dumps(self.to_dict(), indent=2, default=str) + "\n", encoding="utf-8")


def guarded(task_id: str, title: str) -> Callable:
    """Decorator: turn any unexpected exception into an ERROR ``TaskResult``.

    Tasks are called from the GUI; a crash inside one demonstration must be
    reported cleanly rather than bringing down the whole application.
    """

    def decorate(func: Callable[..., TaskResult]) -> Callable[..., TaskResult]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> TaskResult:
            try:
                return func(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001 - deliberately broad at the task boundary
                _log.error("%s failed: %s", task_id, exc)
                _log.debug(traceback.format_exc())
                return TaskResult(
                    task_id=task_id,
                    title=title,
                    status=Status.ERROR,
                    reason=f"{type(exc).__name__}: {exc}",
                )

        return wrapper

    return decorate
