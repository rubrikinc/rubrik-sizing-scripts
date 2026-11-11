"""The certificate store for the HTTPS calls that do not go through the Azure SDK.

``urllib`` trusts only the operating system's store, and a python.org Python on macOS has none until its
"Install Certificates" step has been run, so a plain ``urlopen`` fails there with
CERTIFICATE_VERIFY_FAILED. The Azure SDK and ``requests`` ship ``certifi`` and are not affected. Calls
made with ``urllib`` pass ``ssl_context()`` so they trust the same bundle.

A bundle named in the environment wins, the way it does for ``requests`` and the SDK: a network that
re-signs HTTPS traffic with its own certificate authority needs its bundle, not certifi's. The variables
are read in this order, and the first one that is set and not empty is used: ``SSL_CERT_FILE``,
``REQUESTS_CA_BUNDLE``, ``CURL_CA_BUNDLE``. If it names a file that is not there, a warning says so and
certifi is used instead.

Verification is never turned off. If certifi is missing or its bundle cannot be read, the default
context is used, which is what the call did before.
"""

from __future__ import annotations

import functools
import logging
import os
import ssl
from typing import Optional

logger = logging.getLogger(__name__)

_BUNDLE_VARIABLES = ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE")


def _certifi_path() -> Optional[str]:
    try:
        import certifi
    except ImportError:
        return None
    return certifi.where()


def _bundle_from_environment() -> Optional[str]:
    """The CA bundle the environment names, or None. The first variable that is set wins."""
    for name in _BUNDLE_VARIABLES:
        path = os.environ.get(name, "").strip()
        if not path:
            continue
        if os.path.isfile(path):
            return path
        logger.warning("%s names %s, which is not a file; using the default certificates", name, path)
        return None
    return None


@functools.lru_cache(maxsize=1)
def ssl_context() -> ssl.SSLContext:
    """A verifying context: the bundle the environment names, else certifi's, else the default."""
    for path in (_bundle_from_environment(), _certifi_path()):
        if not path:
            continue
        try:
            return ssl.create_default_context(cafile=path)
        except (OSError, ssl.SSLError) as exc:
            logger.warning("Could not load the certificate bundle %s: %s", path, exc)
    return ssl.create_default_context()
