"""Result panel: status, summary, task-specific view, artifacts and open actions."""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
from typing import Callable

from app.gui.presenter import DisplayModel, display_path

STATUS_COLORS = {"pass": "#1b7f3b", "completed": "#1f5fa8", "fail": "#b3261e", "error": "#b3261e",
                 "na": "#8a5a00"}
MONO = ("Consolas", 10)
THUMB_SIZE = (460, 200)


def _readonly_text(master, height: int) -> ScrolledText:
    text = ScrolledText(master, height=height, wrap="word", font=MONO, relief="solid", borderwidth=1)
    text.configure(state="disabled")
    return text


def _set_text(widget: ScrolledText, content: str) -> None:
    widget.configure(state="normal")
    widget.delete("1.0", "end")
    widget.insert("1.0", content)
    widget.configure(state="disabled")


class ResultPanel(ttk.Frame):
    def __init__(self, master, on_open: Callable[[Path], None], on_open_folder: Callable[[], None]):
        super().__init__(master, padding=(10, 6))
        self._on_open = on_open
        self._on_open_folder = on_open_folder
        self._artifact_paths: list[Path] = []
        self._thumb_image = None
        self.model: DisplayModel | None = None
        self.columnconfigure(0, weight=1)

        self.title_label = ttk.Label(self, text="Result", font=("Segoe UI", 12, "bold"))
        self.title_label.grid(row=0, column=0, sticky="w")
        head = ttk.Frame(self)
        head.grid(row=1, column=0, sticky="ew", pady=(2, 0))
        self.status_label = tk.Label(head, text="No task run yet", font=("Segoe UI", 15, "bold"), fg="#555555")
        self.status_label.pack(side="left")
        self.final_label = tk.Label(head, text="", font=("Segoe UI", 12, "bold"))
        self.final_label.pack(side="left", padx=(16, 0))
        self.reason_label = ttk.Label(self, text="", wraplength=760, foreground="#444444")
        self.reason_label.grid(row=2, column=0, sticky="w", pady=(2, 6))

        ttk.Label(self, text="Summary", font=("Segoe UI", 10, "bold")).grid(row=3, column=0, sticky="w")
        self.summary_text = _readonly_text(self, 10)
        self.summary_text.grid(row=4, column=0, sticky="nsew")
        self.rowconfigure(4, weight=3)

        self.extra_label = ttk.Label(self, text="", font=("Segoe UI", 10, "bold"))
        self.extra_label.grid(row=5, column=0, sticky="w", pady=(8, 0))
        self.extra_frame = ttk.Frame(self)
        self.extra_frame.grid(row=6, column=0, sticky="nsew")
        self.extra_frame.columnconfigure(0, weight=1)
        self.extra_frame.rowconfigure(0, weight=1)
        self.extra_text = _readonly_text(self.extra_frame, 8)
        self.extra_text.grid(row=0, column=0, sticky="nsew")
        self.thumb_label = ttk.Label(self.extra_frame)
        self.thumb_label.grid(row=0, column=1, sticky="n", padx=(8, 0))
        self.rowconfigure(6, weight=2)

        ttk.Label(self, text="Artifacts (double-click to open)", font=("Segoe UI", 10, "bold")
                  ).grid(row=7, column=0, sticky="w", pady=(8, 0))
        box = ttk.Frame(self)
        box.grid(row=8, column=0, sticky="nsew")
        box.columnconfigure(0, weight=1)
        self.artifact_list = tk.Listbox(box, height=5, font=("Consolas", 9), activestyle="none")
        self.artifact_list.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(box, orient="vertical", command=self.artifact_list.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.artifact_list.configure(yscrollcommand=scroll.set)
        self.artifact_list.bind("<Double-Button-1>", self._open_selected_artifact)
        self.rowconfigure(8, weight=1)

        self.actions = ttk.Frame(self)
        self.actions.grid(row=9, column=0, sticky="ew", pady=(8, 0))
        self._hide_extra()

    # ----------------------------------------------------------------- display
    def show(self, model: DisplayModel) -> None:
        self.model = model
        self.title_label.configure(text=model.title)
        self.status_label.configure(text=model.status, fg=STATUS_COLORS.get(model.kind, "#555555"))
        self.final_label.configure(text=model.final,
                                   fg=STATUS_COLORS["pass"] if model.final.endswith("SUCCESSFUL") else
                                   STATUS_COLORS["fail"])
        self.reason_label.configure(text=f"Reason: {model.reason}" if model.reason else "")

        width = max((len(label) for label, _ in model.summary), default=0)
        _set_text(self.summary_text, "\n".join(f"{label.ljust(width)} : {value}" for label, value in model.summary)
                  or "(no summary)")

        if model.extra_text or model.thumbnail:
            self.extra_label.configure(text=model.extra_title or "Preview")
            self.extra_label.grid()
            self.extra_frame.grid()
            _set_text(self.extra_text, model.extra_text)
            if model.extra_text:
                self.extra_text.grid()
                self.thumb_label.grid(row=0, column=1, sticky="n", padx=(8, 0))
            else:                                     # image only: no empty text box
                self.extra_text.grid_remove()
                self.thumb_label.grid(row=0, column=0, sticky="nw", padx=0)
            self._show_thumbnail(model.thumbnail)
        else:
            self._hide_extra()

        self._artifact_paths = list(model.artifacts)
        self.artifact_list.delete(0, "end")
        for path in self._artifact_paths:
            self.artifact_list.insert("end", display_path(path))

        for child in self.actions.winfo_children():
            child.destroy()
        buttons = []
        if model.report:
            buttons.append(("Open Report", lambda p=model.report: self._on_open(p)))
        buttons.append(("Open Output Folder", self._on_open_folder))
        buttons += [(a.label, lambda p=a.path: self._on_open(p)) for a in model.actions]
        for i, (label, command) in enumerate(buttons):
            ttk.Button(self.actions, text=label, command=command).grid(row=i // 5, column=i % 5, padx=(0, 6),
                                                                      pady=2, sticky="w")

    def clear(self) -> None:
        self.model = None
        self.title_label.configure(text="Result")
        self.status_label.configure(text="No task run yet", fg="#555555")
        self.final_label.configure(text="")
        self.reason_label.configure(text="")
        _set_text(self.summary_text, "")
        self._hide_extra()
        self.artifact_list.delete(0, "end")
        self._artifact_paths = []
        for child in self.actions.winfo_children():
            child.destroy()

    def action_labels(self) -> list[str]:
        return [str(child.cget("text")) for child in self.actions.winfo_children()]

    def visible_text(self) -> str:
        """Everything currently shown (used by tests to check nothing secret is displayed)."""
        parts = [self.title_label.cget("text"), self.status_label.cget("text"), self.final_label.cget("text"),
                 self.reason_label.cget("text"), self.summary_text.get("1.0", "end"),
                 self.extra_text.get("1.0", "end"), *self.artifact_list.get(0, "end")]
        return "\n".join(str(p) for p in parts)

    # --------------------------------------------------------------- helpers
    def _hide_extra(self) -> None:
        self.extra_label.grid_remove()
        self.extra_frame.grid_remove()
        _set_text(self.extra_text, "")
        self._show_thumbnail(None)

    def _show_thumbnail(self, path: Path | None) -> None:
        self._thumb_image = None
        if path is not None:
            try:
                from PIL import Image, ImageTk

                with Image.open(path) as img:
                    img.thumbnail(THUMB_SIZE)
                    self._thumb_image = ImageTk.PhotoImage(img.copy())
            except (OSError, ImportError, tk.TclError):
                self._thumb_image = None
        self.thumb_label.configure(image=self._thumb_image or "")

    def _open_selected_artifact(self, _event=None) -> None:
        selection = self.artifact_list.curselection()
        if selection:
            self._on_open(self._artifact_paths[selection[0]])
