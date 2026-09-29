"""Logging setup shared by all modules.

Policy: log *what* happened (sizes, statuses, file names, key fingerprints),
never plaintext contents or secret key material.
"""

from __future__ import annotations

import logging

_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_configured = False


def get_logger(name: str) -> logging.Logger:
    global _configured
    if not _configured:
        logging.basicConfig(level=logging.INFO, format=_FORMAT, datefmt="%H:%M:%S")
        _configured = True
    return logging.getLogger(name)
