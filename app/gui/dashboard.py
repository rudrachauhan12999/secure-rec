"""Left-hand control column: file selection, pipeline buttons, task buttons."""

from __future__ import annotations

from tkinter import ttk
from typing import Callable

from app.gui.components.file_panel import FilePanel
from app.gui.task_registry import INPUT_HINTS, TASKS


class Dashboard(ttk.Frame):
    def __init__(self, master, *, on_browse: Callable[[], None], on_sample: Callable[[], None],
                 on_clear_file: Callable[[], None], on_pipeline: Callable[[bool], None],
                 on_task: Callable[[str], None]):
        super().__init__(master, padding=(10, 6))
        self.columnconfigure(0, weight=1)

        self.file_panel = FilePanel(self, on_browse, on_sample, on_clear_file)
        self.file_panel.grid(row=0, column=0, sticky="ew")

        pipe = ttk.LabelFrame(self, text="Integrated Secure Pipeline", padding=8)
        pipe.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        pipe.columnconfigure(0, weight=1)
        self.pipeline_button = ttk.Button(pipe, text="RUN COMPLETE SECURE PIPELINE",
                                          command=lambda: on_pipeline(False))
        self.tamper_button = ttk.Button(pipe, text="RUN PIPELINE WITH TAMPERING",
                                        command=lambda: on_pipeline(True))
        self.pipeline_button.grid(row=0, column=0, sticky="ew")
        self.tamper_button.grid(row=1, column=0, sticky="ew", pady=(4, 0))

        tasks = ttk.LabelFrame(self, text="Individual Tasks", padding=8)
        tasks.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        tasks.columnconfigure((0, 1), weight=1, uniform="tasks")
        self.task_buttons: dict[str, ttk.Button] = {}
        for i, spec in enumerate(TASKS):
            button = ttk.Button(tasks, text=f"{spec.number}  {spec.label}", command=lambda k=spec.key: on_task(k))
            button.grid(row=i // 2, column=i % 2, sticky="ew", padx=2, pady=2)
            self.task_buttons[spec.key] = button
        hint = (f"Task 3 {INPUT_HINTS['image']}; Task 4 {INPUT_HINTS['benchmark']}; "
                f"Tasks 6 and 12: {INPUT_HINTS['none']}.")
        ttk.Label(tasks, text=hint, wraplength=340, foreground="#555555").grid(row=6, column=0, columnspan=2,
                                                                                 sticky="w", pady=(6, 0))

    @property
    def job_buttons(self) -> list[ttk.Button]:
        """Buttons disabled while a job runs (all jobs share outputs/ and keys/)."""
        return [*self.file_panel.buttons, self.pipeline_button, self.tamper_button, *self.task_buttons.values()]
