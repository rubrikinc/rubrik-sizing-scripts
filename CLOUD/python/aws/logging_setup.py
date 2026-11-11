"""Logging setup for the standalone AWS CLI.

This tool ships independently (CloudShell pip package) and cannot import the
repo-root ``obs`` package, so it implements the shared logging convention by
hand. The convention — ``"<time> <LEVEL> <logger> — <message>"``, default INFO,
``--verbose`` raises to DEBUG — is documented in docs/observability.md and is the
single source of truth that this file, azure/logging_setup.py, and
gcp/logging_setup.py each mirror.

A CLI has no cross-process correlation, so (unlike ``obs``) there is no ``rid``
field here. The level name is ANSI-colorised, which is appropriate for an
interactive terminal tool.
"""

from __future__ import annotations

import logging
import os

from runlog_core import TranscriptHandler


class C:
    """ANSI escape codes, shared with main.py's terminal box drawing."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    RED = "\033[31m"
    WHITE = "\033[97m"


class ColorFormatter(logging.Formatter):
    _COLORS = {
        logging.DEBUG: C.DIM,
        logging.INFO: C.CYAN,
        logging.WARNING: C.YELLOW,
        logging.ERROR: C.RED,
    }

    def format(self, record: logging.LogRecord) -> str:
        color = self._COLORS.get(record.levelno, "")
        record.levelname = f"{color}{record.levelname:<7}{C.RESET}"
        return super().format(record)


def setup_logging(verbose: bool = False) -> None:
    """Configure the root logger. Idempotent — safe to call more than once.

    The root logger is left at DEBUG and the console verbosity is gated on the
    stream handler itself, so a later :func:`add_log_file` can attach a handler
    that captures the full DEBUG run log to disk without flooding the terminal.
    """
    handler = logging.StreamHandler()
    handler.setFormatter(
        ColorFormatter(
            f"{C.DIM}%(asctime)s{C.RESET} %(levelname)s %(name)s — %(message)s",
            datefmt="%H:%M:%S",
        )
    )
    handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.handlers = [handler]


def add_log_file(path: str | os.PathLike[str]) -> logging.Handler:
    """Attach the run log: a plain-text transcript of what the screen shows.

    The log is not verbose, whatever ``--verbose`` does to the console: INFO and above, library
    debug noise left out, no colour codes. The level name is taken from the record's number because
    the console formatter above rewrites ``record.levelname`` with colour codes. Returns the handler so
    the caller can ``close()`` and detach it before zipping.
    """
    handler = TranscriptHandler(str(path), logging.INFO)
    logging.getLogger().addHandler(handler)
    return handler
