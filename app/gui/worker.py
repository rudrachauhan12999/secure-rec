"""Run backend jobs off the Tk main thread.

Tkinter widgets may only be touched from the main thread, so the worker
thread puts its outcome on a queue and the main loop polls it with
``after()`` (passed in as ``schedule`` so the class is testable without Tk).
"""

from __future__ import annotations

import queue
import threading
import traceback
from typing import Any, Callable

from core.logging_utils import get_logger

_log = get_logger(__name__)
POLL_MS = 100


class BackgroundWorker:
    """The worker thread sees only ``job`` and a queue.

    Callbacks (which reference Tk widgets) stay on the main thread. If the
    thread held the last reference to a Tk object, that object would be
    garbage-collected on the wrong thread, which corrupts the Tcl interpreter.
    ``job`` must therefore not capture widgets either.
    """

    def __init__(self, schedule: Callable[[int, Callable[[], None]], Any]):
        self._schedule = schedule
        self._queue: queue.Queue = queue.Queue()
        self._callbacks: tuple[Callable[[Any], None], Callable[[BaseException], None]] | None = None
        self.busy = False

    def submit(self, job: Callable[[], Any], on_done: Callable[[Any], None],
               on_error: Callable[[BaseException], None]) -> bool:
        """Start ``job`` in a thread; returns False if another job is still running."""
        if self.busy:
            return False
        self.busy = True
        self._callbacks = (on_done, on_error)
        results = self._queue

        def target() -> None:          # closes over ``job`` and ``results`` only
            try:
                results.put((True, job()))
            except BaseException as exc:  # noqa: BLE001 - reported to the UI, never swallowed silently
                _log.debug(traceback.format_exc())
                results.put((False, exc))

        threading.Thread(target=target, daemon=True).start()
        self._schedule(POLL_MS, self._poll)
        return True

    def _poll(self) -> None:
        try:
            ok, value = self._queue.get_nowait()
        except queue.Empty:
            self._schedule(POLL_MS, self._poll)
            return
        on_done, on_error = self._callbacks
        self._callbacks = None
        self.busy = False
        (on_done if ok else on_error)(value)
