"""Bottom status line with an indeterminate progress indicator."""

from __future__ import annotations

from tkinter import ttk


class StatusBar(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=(8, 4))
        self.columnconfigure(0, weight=1)
        self.label = ttk.Label(self, text="Ready")
        self.label.grid(row=0, column=0, sticky="w")
        self.progress = ttk.Progressbar(self, mode="indeterminate", length=180)
        self.progress.grid(row=0, column=1, sticky="e")

    def busy(self, message: str) -> None:
        self.label.configure(text=message)
        self.progress.start(12)

    def idle(self, message: str = "Ready") -> None:
        self.progress.stop()
        self.progress.configure(value=0)
        self.label.configure(text=message)

    @property
    def text(self) -> str:
        return str(self.label.cget("text"))
