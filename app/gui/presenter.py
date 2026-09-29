"""Turns a TaskResult into what the result panel shows (no Tkinter, no crypto).

Deliberately compact: status, the task's own summary lines, a task-specific
view where useful (pipeline stages, benchmark table, Kerberos transcript),
safe artifact links and "open" actions.  Full reports stay in report.txt.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from core.config import KEYS_DIR, PROJECT_ROOT
from core.results import Status, TaskResult
from pipeline import receiver as rx
from pipeline import secure_pipeline
from tasks import task04_performance

MAX_VALUE_CHARS = 180
MAX_EXTRA_LINES = 60

STATUS_KIND = {
    Status.PASS: "pass",
    Status.COMPLETED: "completed",
    Status.FAIL: "fail",
    Status.ERROR: "error",
    Status.NOT_APPLICABLE: "na",
}

# artifact file name -> button label (order = button order)
ACTION_LABELS = {
    "comparison_original_ecb_cbc.png": "Open Comparison Image",
    "original_rgb.png": "Open Original Image",
    "encrypted_ecb.png": "Open ECB Image",
    "encrypted_cbc.png": "Open CBC Image",
    "benchmark_chart.png": "Open Chart",
    "benchmark_results.csv": "Open Benchmark CSV",
    "public_transcript.json": "Open Public Transcript",
    "tamper_log.csv": "Open Tamper Log",
    "sha256sums.txt": "Open Hashes",
    "sender_public_key.pem": "Open Public Key",
    "certificate_info.txt": "Open Certificate Information",
    "transcript.txt": "Open Transcript",
    "signed_structure.json": "Open Signed Structure",
}
THUMBNAILS = ("comparison_original_ecb_cbc.png", "benchmark_chart.png")

PIPELINE_STAGE_LABELS = {
    rx.STAGE_FORMAT: "Package received and parsed",
    rx.STAGE_CERT: "Certificate verification",
    rx.STAGE_IDENTITY: "Sender identity (pinned certificate)",
    rx.STAGE_SIGNATURE: "Digital signature verification",
    rx.STAGE_KEY: "RSA key recovery",
    rx.STAGE_DECRYPT: "AES decryption",
    rx.STAGE_INTEGRITY: "SHA-256 integrity",
    secure_pipeline.STAGE_BYTES: "File recovery (byte-for-byte match)",
}
OK, FAILED, NOT_RUN = "✓", "✗", "–"


@dataclass(frozen=True)
class Action:
    label: str
    path: Path


@dataclass
class DisplayModel:
    title: str
    status: str
    kind: str
    reason: str = ""
    summary: list[tuple[str, str]] = field(default_factory=list)
    extra_title: str = ""
    extra_text: str = ""
    final: str = ""
    artifacts: list[Path] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)
    thumbnail: Path | None = None
    report: Path | None = None
    output_dir: Path | None = None


def _is_secret_path(path: Path) -> bool:
    try:
        path.resolve().relative_to(KEYS_DIR.resolve())
        return True
    except ValueError:
        pass
    name = path.name.lower()
    return "private" in name or name.endswith((".key", ".p12", ".pfx"))


def safe_artifacts(paths: list[Path]) -> list[Path]:
    """Existing artifacts only, never anything under keys/ or named like a private key."""
    return [Path(p) for p in paths if Path(p).is_file() and not _is_secret_path(Path(p))]


def _clean(value: str) -> str:
    if "PRIVATE KEY" in value:
        return "[hidden]"
    value = " ".join(value.split())
    return value if len(value) <= MAX_VALUE_CHARS else value[:MAX_VALUE_CHARS - 3] + "..."


def display_path(path: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


def _limit(text: str) -> str:
    lines = text.splitlines()
    if len(lines) <= MAX_EXTRA_LINES:
        return text
    return "\n".join(lines[:MAX_EXTRA_LINES] + [f"... ({len(lines) - MAX_EXTRA_LINES} more lines in the report)"])


# ------------------------------------------------------------ pipeline view
def pipeline_view(result: TaskResult) -> tuple[str, str, str]:
    """(stage checklist, final line, reason) read from the pipeline's own result data."""
    data = result.data
    if result.status is Status.ERROR or "stages" not in data:
        return "", "SECURE TRANSFER NOT COMPLETED", result.reason
    stages = {s["stage"]: s for s in data["stages"]}
    lines = [f"{OK} Input accepted ({data.get('file')}, {data.get('size_bytes')} bytes)",
             f"{OK} AES-128-CBC encryption (sender)",
             f"{OK} RSA-OAEP key protection (sender)",
             f"{OK} Digital signature created (sender)"]
    for name in [*rx.RECEIVER_STAGES, secure_pipeline.STAGE_BYTES]:
        stage = stages.get(name)
        mark = NOT_RUN if stage is None else (OK if stage["ok"] else FAILED)
        suffix = "not run - stopped at earlier failure" if stage is None else stage["detail"]
        lines.append(f"{mark} {PIPELINE_STAGE_LABELS[name]}: {_clean(suffix)}")

    if data.get("accepted") and data.get("byte_match"):
        return "\n".join(lines), "SECURE TRANSFER SUCCESSFUL", ""
    failed = data.get("failed_stage")
    detail = next((s["detail"] for s in data["stages"] if not s["ok"]), "")
    reason = f"{PIPELINE_STAGE_LABELS.get(failed, failed)} failed - {_clean(detail)}"
    if data.get("mode") != "normal" and result.status is Status.PASS:
        reason += "  (tampering demonstration: the modification was detected as expected)"
    return "\n".join(lines), "SECURE TRANSFER REJECTED", reason


# ------------------------------------------------------------------ present
def present(result: TaskResult) -> DisplayModel:
    artifacts = safe_artifacts(result.artifacts)
    by_name: dict[str, Path] = {}
    for p in artifacts:
        by_name.setdefault(p.name, p)
    report = by_name.get("report.txt")
    output_dir = report.parent if report else (artifacts[0].parent if artifacts else None)

    model = DisplayModel(
        title=result.title,
        status=result.status.value,
        kind=STATUS_KIND.get(result.status, "error"),
        reason=_clean(result.reason) if result.reason else "",
        summary=[(label, _clean(value)) for label, value in result.summary],
        artifacts=artifacts,
        report=report,
        output_dir=output_dir,
    )
    model.actions = [Action(label, by_name[name]) for name, label in ACTION_LABELS.items() if name in by_name]
    recovered = [p for p in artifacts if p.name.startswith("recovered_")]
    if recovered:
        model.actions.append(Action("Open Recovered File", recovered[0]))
    model.thumbnail = next((by_name[n] for n in THUMBNAILS if n in by_name), None)

    if result.task_id == secure_pipeline.TASK_ID:
        model.extra_title = "Pipeline stages"
        model.extra_text, model.final, stage_reason = pipeline_view(result)
        if stage_reason and result.status is not Status.ERROR:
            model.reason = stage_reason
        if result.data.get("mode", "normal") != "normal" and result.status is Status.PASS:
            model.status = f"{result.status.value} (demonstration: tampering detected)"
    elif result.task_id == "task04" and result.data.get("rows"):
        model.extra_title = "Benchmark (median of repeated runs)"
        model.extra_text = task04_performance.format_table(result.data["rows"])
    elif result.task_id in ("task07", "task12") and "transcript.txt" in by_name:
        model.extra_title = "Transcript"
        model.extra_text = _limit(by_name["transcript.txt"].read_text(encoding="utf-8"))
    return model
