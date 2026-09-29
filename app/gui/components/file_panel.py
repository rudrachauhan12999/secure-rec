"""Selected-file panel: path, name, type, size, SHA-256."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable

from app.gui.task_registry import FileSummary


class FilePanel(ttk.LabelFrame):
    FIELDS = ("Name", "Type", "Size", "SHA-256", "Image")

    def __init__(self, master, on_browse: Callable[[], None], on_sample: Callable[[], None],
                 on_clear: Callable[[], None]):
        super().__init__(master, text="Selected File", padding=8)
        self.columnconfigure(1, weight=1)

        self.path_var = tk.StringVar(value="(no file selected)")
        ttk.Entry(self, textvariable=self.path_var, state="readonly").grid(row=0, column=0, columnspan=2,
                                                                          sticky="ew", pady=(0, 6))
        buttons = ttk.Frame(self)
        buttons.grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 6))
        self.browse_button = ttk.Button(buttons, text="Select File...", command=on_browse)
        self.sample_button = ttk.Button(buttons, text="Use Sample Dataset", command=on_sample)
        self.clear_button = ttk.Button(buttons, text="Clear", command=on_clear)
        for i, b in enumerate((self.browse_button, self.sample_button, self.clear_button)):
            b.grid(row=0, column=i, padx=(0, 6))

        self.vars: dict[str, tk.StringVar] = {}
        for row, name in enumerate(self.FIELDS, start=2):
            ttk.Label(self, text=f"{name}:").grid(row=row, column=0, sticky="nw", padx=(0, 8))
            var = tk.StringVar(value="-")
            ttk.Label(self, textvariable=var, wraplength=300, font=("Consolas", 9) if name == "SHA-256" else None
                      ).grid(row=row, column=1, sticky="w")
            self.vars[name] = var
        self.message = ttk.Label(self, text="", foreground="#b3261e", wraplength=340)
        self.message.grid(row=len(self.FIELDS) + 2, column=0, columnspan=2, sticky="w", pady=(4, 0))

    @property
    def buttons(self) -> list[ttk.Button]:
        return [self.browse_button, self.sample_button, self.clear_button]

    def show(self, summary: FileSummary | None, message: str = "") -> None:
        if summary is None:
            self.path_var.set("(no file selected)")
            for var in self.vars.values():
                var.set("-")
        else:
            self.path_var.set(str(summary.path))
            self.vars["Name"].set(summary.name)
            self.vars["Type"].set(summary.type_label)
            self.vars["Size"].set(f"{summary.human_size} ({summary.size_bytes:,} bytes)")
            self.vars["SHA-256"].set(summary.sha256)
            self.vars["Image"].set("yes (Task 3 available)" if summary.is_image else "no (Task 3 needs an image)")
        self.message.configure(text=message)

    def show_pending(self, path: str) -> None:
        self.path_var.set(path)
        for var in self.vars.values():
            var.set("...")
        self.message.configure(text="")
