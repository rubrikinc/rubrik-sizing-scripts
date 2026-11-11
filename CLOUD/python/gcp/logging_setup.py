"""Logging setup for the standalone GCP CLI.

Ships independently (Google Cloud Shell) and cannot import the repo-root ``obs``
package, so it implements the shared logging convention by hand. The convention
— ``"<time> <LEVEL> <logger> — <message>"``, ``--verbose`` raises to DEBUG,
otherwise WARNING so the Rich terminal UI stays clean — is documented in
docs/observability.md and mirrored by aws/ and azure/ logging_setup.py.

The diagnostic ``logging`` channel goes to stderr; user-facing output is handled
separately by Rich in main.py.
"""

from __future__ import annotations

import logging
import os
import re
import sys

from runlog_core import TranscriptHandler

LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s — %(message)s"
DATE_FORMAT = "%H:%M:%S"


class _ReportedClientErrors(logging.Filter):
    """Drop the Google API client's own warning about a 4xx answer, such as
    ``Encountered 403 Forbidden with reason "notAuthorized"``.

    It names no project or service, and the collector that made the call reports the same
    failure with both. A 429 is kept: that is a rate limit worth seeing.
    """

    _PATTERN = re.compile(r"Encountered (?!429\b)4\d\d ")

    def filter(self, record: logging.LogRecord) -> bool:
        return not self._PATTERN.search(record.getMessage())


def setup_logging(verbose: bool = False) -> None:
    """Configure root logging to stderr. DEBUG when verbose, else WARNING.

    The root logger is left at DEBUG and the console verbosity is gated on the
    stream handler itself, so a later :func:`add_log_file` can attach a handler
    that captures the full DEBUG run log to disk without flooding the terminal.
    """
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))
    handler.setLevel(logging.DEBUG if verbose else logging.WARNING)
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.handlers = [handler]
    client_http = logging.getLogger("googleapiclient.http")
    if not any(isinstance(f, _ReportedClientErrors) for f in client_http.filters):
        client_http.addFilter(_ReportedClientErrors())


def add_log_file(path: str | os.PathLike[str]) -> logging.Handler:
    """Attach the run log: a plain-text transcript of what the screen shows.

    The log is not verbose, whatever ``--verbose`` does to the console: it holds the WARNING and
    ERROR lines the screen shows plus everything the Rich console prints, with library debug noise
    left out and no colour codes. Returns the handler so the caller can ``close()`` and detach it
    before zipping.
    """
    handler = TranscriptHandler(str(path), logging.WARNING)
    logging.getLogger().addHandler(handler)
    return handler
