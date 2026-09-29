"""SECURE-REC main window.

Orchestration only: it collects input, calls ``app.gui.task_registry``
(which calls the existing task/pipeline ``run()`` functions) on a worker
thread, and shows the returned TaskResult through ``presenter``.
"""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any, Callable

from app.gui import file_opener, task_registry
from app.gui.components.result_panel import ResultPanel
from app.gui.components.status_bar import StatusBar
from app.gui.dashboard import Dashboard
from app.gui.presenter import DisplayModel, present
from app.gui.worker import BackgroundWorker
from core.config import BENCHMARKS_DIR, DEFAULT_SAMPLE_FILE, OUTPUT_DIR
from core.results import Status, TaskResult

APP_TITLE = "SECURE-REC - Secure File Exchange & Cryptographic Analysis"
FILE_TYPES = [("All files", "*.*"), ("Text", "*.txt *.csv"), ("PDF", "*.pdf"),
              ("Images", "*.png *.jpg *.jpeg *.bmp *.gif"), ("Binary", "*.bin *.dat")]


class SecureRecApp:
    def __init__(self, root: tk.Tk, output_root: Path | None = None, keys_root: Path | None = None,
                 launcher: Callable[[Path], None] = file_opener.system_open, load_sample: bool = True,
                 show_dialogs: bool = True,
                 ask_open_file: Callable[..., Any] = filedialog.askopenfilename):
        self.root = root
        self.output_root = output_root or OUTPUT_DIR
        self.keys_root = keys_root              # None -> the tasks' own defaults under keys/
        self.launcher = launcher
        self.show_dialogs = show_dialogs
        self.ask_open_file = ask_open_file
        self.selected: task_registry.FileSummary | None = None
        self.worker = BackgroundWorker(root.after)

        root.title(APP_TITLE)
        self._size_window()
        self._build()
        if load_sample and DEFAULT_SAMPLE_FILE.exists():
            self.select_path(DEFAULT_SAMPLE_FILE)

    # ------------------------------------------------------------------ layout
    def _size_window(self) -> None:
        """Fit the screen (DPI scaling makes fixed pixel sizes unreliable)."""
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        width, height = min(int(sw * 0.86), 1700), min(int(sh * 0.86), 1050)
        self.root.geometry(f"{width}x{height}+{max((sw - width) // 2, 0)}+{max(int(sh * 0.02), 0)}")
        self.root.minsize(min(1000, sw), min(640, sh))

    def _build(self) -> None:
        header = ttk.Frame(self.root, padding=(12, 8, 12, 0))
        header.pack(fill="x")
        ttk.Label(header, text="SECURE-REC", font=("Segoe UI", 18, "bold")).pack(side="left")
        ttk.Label(header, text="Secure File Exchange & Cryptographic Analysis Platform  (educational)",
                  font=("Segoe UI", 11), foreground="#555555").pack(side="left", padx=(12, 0), pady=(6, 0))
        self.open_outputs_button = ttk.Button(header, text="Open Outputs Folder", command=self.open_outputs_folder)
        self.open_outputs_button.pack(side="right")
        self.clear_results_button = ttk.Button(header, text="Clear Results", command=self.clear_results)
        self.clear_results_button.pack(side="right", padx=(0, 6))
        ttk.Separator(self.root).pack(fill="x", pady=(8, 0))

        self.status_bar = StatusBar(self.root)
        self.status_bar.pack(side="bottom", fill="x")
        ttk.Separator(self.root).pack(side="bottom", fill="x")

        body = ttk.PanedWindow(self.root, orient="horizontal")
        body.pack(fill="both", expand=True)
        self.dashboard = Dashboard(body, on_browse=self.browse, on_sample=self.use_sample,
                                   on_clear_file=self.clear_selection, on_pipeline=self.run_pipeline,
                                   on_task=self.run_task)
        self.result_panel = ResultPanel(body, on_open=self.open_path, on_open_folder=self.open_result_folder)
        body.add(self.dashboard, weight=0)
        body.add(self.result_panel, weight=1)

    @property
    def file_panel(self):
        return self.dashboard.file_panel

    @property
    def allowed_roots(self) -> list[Path]:
        return [self.output_root, BENCHMARKS_DIR]

    # --------------------------------------------------------------- file input
    def browse(self) -> None:
        path = self.ask_open_file(title="Select a file to process", filetypes=FILE_TYPES)
        if path:
            self.select_path(Path(path))

    def use_sample(self) -> None:
        self.select_path(DEFAULT_SAMPLE_FILE)

    def select_path(self, path: str | Path) -> None:
        self.file_panel.show_pending(str(path))
        self._start(f"Reading {Path(path).name} ...", lambda: task_registry.inspect_file(path),
                    self._file_selected, self._file_failed)

    def _file_selected(self, summary: task_registry.FileSummary) -> None:
        self.selected = summary
        self.file_panel.show(summary)
        self.status_bar.idle(f"Selected {summary.name} ({summary.human_size})")

    def _file_failed(self, exc: BaseException) -> None:
        self.selected = None
        self.file_panel.show(None, message=str(exc))
        self.status_bar.idle(f"File not accepted: {exc}")

    def clear_selection(self) -> None:
        self.selected = None
        self.file_panel.show(None, message="No file selected. Tasks 4, 6 and 12 still work without one.")
        self.status_bar.idle("Selection cleared")

    @property
    def selected_path(self) -> Path | None:
        return self.selected.path if self.selected else None

    # -------------------------------------------------------------------- jobs
    def run_task(self, key: str) -> None:
        spec = task_registry.TASK_BY_KEY[key]
        # plain values only: the job runs on a worker thread and must not reference Tk objects
        selected, output_root, keys_root = self.selected_path, self.output_root, self.keys_root
        self._start(f"Running Task {spec.number} - {spec.label} ...",
                    lambda: task_registry.run_task(key, selected, output_root, keys_root),
                    self._show_result, lambda exc: self._show_exception(spec.key, spec.title, exc))

    def run_pipeline(self, tamper: bool) -> None:
        selected, output_root, keys_root = self.selected_path, self.output_root, self.keys_root
        label = "secure pipeline with tampering" if tamper else "complete secure pipeline"
        self._start(f"Running {label} ...",
                    lambda: task_registry.run_pipeline(selected, tamper, output_root, keys_root),
                    self._show_result,
                    lambda exc: self._show_exception(task_registry.PIPELINE_KEY, "Integrated pipeline", exc))

    def _start(self, message: str, job: Callable[[], Any], on_done: Callable[[Any], None],
               on_error: Callable[[BaseException], None]) -> None:
        def done(value: Any) -> None:
            self._set_buttons("normal")
            on_done(value)

        def failed(exc: BaseException) -> None:
            self._set_buttons("normal")
            on_error(exc)

        if not self.worker.submit(job, done, failed):
            self.status_bar.label.configure(text="Please wait - another operation is still running")
            return
        self._set_buttons("disabled")
        self.status_bar.busy(message)

    def _set_buttons(self, state: str) -> None:
        for button in [*self.dashboard.job_buttons, self.clear_results_button]:
            button.configure(state=state)

    @property
    def busy(self) -> bool:
        return self.worker.busy

    # ------------------------------------------------------------------ output
    def _show_result(self, result: TaskResult) -> DisplayModel:
        model = present(result)
        self.result_panel.show(model)
        self.status_bar.idle(f"{result.title}: {result.status.value}" + (f" - {model.final}" if model.final else ""))
        return model

    def _show_exception(self, task_id: str, title: str, exc: BaseException) -> None:
        self._show_result(TaskResult(task_id, title, status=Status.ERROR, reason=f"{type(exc).__name__}: {exc}"))

    def clear_results(self) -> None:
        self.result_panel.clear()
        self.status_bar.idle("Results cleared")

    def open_path(self, path: Path) -> None:
        try:
            file_opener.open_path(path, self.allowed_roots, self.launcher)
            self.status_bar.idle(f"Opened {Path(path).name}")
        except (file_opener.UnsafePathError, OSError) as exc:
            self.status_bar.idle(f"Cannot open: {exc}")
            if self.show_dialogs:
                messagebox.showwarning("SECURE-REC", str(exc), parent=self.root)

    def open_result_folder(self) -> None:
        model = self.result_panel.model
        self.open_path(model.output_dir if model and model.output_dir else self.output_root)

    def open_outputs_folder(self) -> None:
        self.output_root.mkdir(parents=True, exist_ok=True)
        self.open_path(self.output_root)


def launch() -> None:
    root = tk.Tk()
    try:
        ttk.Style(root).theme_use("vista" if "vista" in ttk.Style(root).theme_names() else "clam")
    except tk.TclError:
        pass
    SecureRecApp(root)
    root.mainloop()
