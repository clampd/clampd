"""Clampd DSN parsing.

A DSN supplies ``gateway_url`` + ``api_key`` from one string. Set ``CLAMPD_DSN``
or pass ``dsn=`` to :func:`clampd.init`.

Format::

    clampd://<org_key>@<host>[:<port>]      # TLS
    clampd+http://<org_key>@<host>:<port>   # plaintext (local dev)

``<org_key>`` is the org API key (``ag_live_…`` / ``ag_test_…``). When the host
is omitted, the managed cloud gateway is used.

Keep these semantics identical to the TypeScript SDK (src/dsn.ts).
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

DEFAULT_GATEWAY_URL = "https://gateway.clampd.dev"

_TLS_SCHEMES = {"clampd", "clampd+https", "https"}
_PLAINTEXT_SCHEMES = {"clampd+http", "http"}


@dataclass(frozen=True)
class Dsn:
    gateway_url: str
    api_key: str


def parse_dsn(dsn: str) -> Dsn:
    raw = (dsn or "").strip()
    if not raw:
        raise ValueError("Empty CLAMPD_DSN. Expected clampd://<org_key>@<host>")

    parts = urlsplit(raw)
    scheme = parts.scheme.lower()
    if scheme in _TLS_SCHEMES:
        proto = "https"
    elif scheme in _PLAINTEXT_SCHEMES:
        proto = "http"
    else:
        raise ValueError(
            f"Invalid CLAMPD_DSN scheme {parts.scheme!r}. "
            "Expected clampd://<org_key>@<host> (or clampd+http:// for local dev)."
        )

    org_key = parts.username or ""
    if not org_key:
        raise ValueError(
            "CLAMPD_DSN is missing the org key. Expected clampd://<org_key>@<host>."
        )

    if parts.hostname:
        gateway_url = f"{proto}://{parts.hostname}"
        if parts.port:
            gateway_url += f":{parts.port}"
    else:
        gateway_url = DEFAULT_GATEWAY_URL

    return Dsn(gateway_url=gateway_url, api_key=org_key)
