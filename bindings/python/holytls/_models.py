"""Plain Python value types returned/consumed by the binding: the enums that
mirror the C ABI, a case-insensitive ``Headers`` map, the ``Response``, and the
exception hierarchy. No cffi here — this module is import-safe even if the
native extension is missing."""

from __future__ import annotations

import enum
import json as _json
from typing import Dict, Iterable, Iterator, List, Optional, Tuple, Union

HeaderInput = Union[Dict[str, str], Iterable[Tuple[str, str]], None]


class Method(enum.IntEnum):
    """HTTP method (values match holytls_method in the C ABI)."""

    GET = 0
    POST = 1
    PUT = 2
    DELETE = 3
    HEAD = 4
    PATCH = 5
    OPTIONS = 6

    @classmethod
    def coerce(cls, value: Union["Method", str, int]) -> "Method":
        if isinstance(value, Method):
            return value
        if isinstance(value, int):
            return cls(value)
        return cls[str(value).strip().upper()]


class HttpVersion(enum.IntEnum):
    """Wire-protocol selection (matches holytls_http_version)."""

    AUTO = 0  # Chrome-faithful: H2, then H3 once an origin advertises alt-svc
    HTTP_1 = 1
    HTTP_2 = 2
    HTTP_3 = 3  # requires a dual-transport client

    @classmethod
    def coerce(cls, value: Union["HttpVersion", str, int]) -> "HttpVersion":
        if isinstance(value, HttpVersion):
            return value
        if isinstance(value, int):
            return cls(value)
        key = str(value).strip().lower().replace("/", "").replace(".", "")
        return {
            "auto": cls.AUTO,
            "h1": cls.HTTP_1,
            "http1": cls.HTTP_1,
            "http11": cls.HTTP_1,
            "1": cls.HTTP_1,
            "h2": cls.HTTP_2,
            "http2": cls.HTTP_2,
            "2": cls.HTTP_2,
            "h3": cls.HTTP_3,
            "http3": cls.HTTP_3,
            "3": cls.HTTP_3,
        }[key]


class FetchMode(enum.IntEnum):
    """Fetch Metadata context (matches holytls_fetch_mode). DEFAULT keeps the
    profile's static navigation Sec-Fetch-* headers."""

    DEFAULT = 0
    NAVIGATE = 1
    CORS = 2
    NO_CORS = 3
    SAME_ORIGIN = 4


class Profile(enum.IntEnum):
    """Emulation profile (matches holytls_profile_id)."""

    CHROME = 0  # newest Chrome (currently 149)
    CHROME_149 = 1
    CHROME_148 = 2
    FIREFOX_151 = 3
    FIREFOX = 3  # newest Firefox (currently 151)

    @classmethod
    def coerce(cls, value: Union["Profile", str, int]) -> "Profile":
        if isinstance(value, Profile):
            return value
        if isinstance(value, int):
            return cls(value)
        key = str(value).strip().lower().replace("-", "").replace("_", "").replace(" ", "")
        return {
            "chrome": cls.CHROME,
            "chrome149": cls.CHROME_149,
            "chrome148": cls.CHROME_148,
            "firefox": cls.FIREFOX,
            "firefox151": cls.FIREFOX_151,
        }[key]


class HolyTLSError(Exception):
    """Base class for every error raised by the binding."""


class TransportError(HolyTLSError):
    """A transport/TLS/HTTP-framing failure: no HTTP response was produced
    (DNS failure, connection refused, TLS error, timeout, …)."""


class StatusError(HolyTLSError):
    """Raised by Response.raise_for_status() for a 4xx/5xx HTTP status."""

    def __init__(self, message: str, response: "Response"):
        super().__init__(message)
        self.response = response


class WebSocketError(HolyTLSError):
    """A WebSocket handshake or protocol failure."""


class ConnectionClosed(WebSocketError):
    """Raised by WebSocket.recv() when the peer closed the connection. Carries
    the RFC 6455 close `code` (0 if none) and the optional `reason` text."""

    def __init__(self, code: int = 0, reason: str = ""):
        super().__init__(f"websocket closed (code={code})"
                         + (f": {reason}" if reason else ""))
        self.code = code
        self.reason = reason


class Headers:
    """An ordered, case-insensitive view of response headers. Preserves wire
    order and duplicates (a server may send several ``set-cookie`` lines);
    ``__getitem__``/``get`` return the first match, ``get_all`` every match."""

    __slots__ = ("_items",)

    def __init__(self, items: Optional[Iterable[Tuple[str, str]]] = None):
        self._items: List[Tuple[str, str]] = list(items or [])

    def get(self, name: str, default: Optional[str] = None) -> Optional[str]:
        low = name.lower()
        for k, v in self._items:
            if k.lower() == low:
                return v
        return default

    def get_all(self, name: str) -> List[str]:
        low = name.lower()
        return [v for k, v in self._items if k.lower() == low]

    def __getitem__(self, name: str) -> str:
        v = self.get(name)
        if v is None:
            raise KeyError(name)
        return v

    def __contains__(self, name: str) -> bool:
        return self.get(name) is not None

    def __iter__(self) -> Iterator[Tuple[str, str]]:
        return iter(self._items)

    def items(self) -> List[Tuple[str, str]]:
        return list(self._items)

    def keys(self) -> List[str]:
        return [k for k, _ in self._items]

    def __len__(self) -> int:
        return len(self._items)

    def __repr__(self) -> str:
        return f"Headers({self._items!r})"


class Timing:
    """Per-request timing breakdown in milliseconds. Setup phases (dns/tcp/tls)
    are 0 when a request reused a warm pooled connection."""

    __slots__ = ("dns_ms", "tcp_ms", "tls_ms", "total_ms")

    def __init__(self, dns_ms: int, tcp_ms: int, tls_ms: int, total_ms: int):
        self.dns_ms = dns_ms
        self.tcp_ms = tcp_ms
        self.tls_ms = tls_ms
        self.total_ms = total_ms

    def __repr__(self) -> str:
        return (
            f"Timing(dns_ms={self.dns_ms}, tcp_ms={self.tcp_ms}, "
            f"tls_ms={self.tls_ms}, total_ms={self.total_ms})"
        )


class Response:
    """A fully-buffered HTTP response.

    ``ok`` is TRANSPORT success (the request completed at the TLS/HTTP level),
    NOT the HTTP status — a 404 has ``ok=True`` and ``status_code=404``. When
    ``ok`` is False, ``error`` holds the failure reason and the body/headers are
    empty.
    """

    __slots__ = (
        "ok",
        "status_code",
        "error",
        "headers",
        "content",
        "url",
        "alpn",
        "resumed",
        "early_data",
        "timing",
    )

    def __init__(
        self,
        *,
        ok: bool,
        status_code: int,
        error: Optional[str],
        headers: Headers,
        content: bytes,
        url: str,
        alpn: str,
        resumed: bool,
        early_data: bool,
        timing: Timing,
    ):
        self.ok = ok
        self.status_code = status_code
        self.error = error
        self.headers = headers
        self.content = content
        self.url = url
        self.alpn = alpn
        self.resumed = resumed
        self.early_data = early_data
        self.timing = timing

    @property
    def text(self) -> str:
        """The body decoded as text. Uses the charset from Content-Type when
        present, else UTF-8; undecodable bytes are replaced (never raises)."""
        return self.content.decode(self._charset(), errors="replace")

    def _charset(self) -> str:
        ctype = self.headers.get("content-type", "") or ""
        for part in ctype.split(";"):
            part = part.strip().lower()
            if part.startswith("charset="):
                return part[len("charset="):].strip().strip('"') or "utf-8"
        return "utf-8"

    def json(self, **kwargs):
        """Parse the body as JSON (stdlib ``json``)."""
        return _json.loads(self.text, **kwargs)

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status_code < 400

    @property
    def is_success(self) -> bool:
        return self.ok and 200 <= self.status_code < 300

    def raise_for_status(self) -> "Response":
        """Raise on a transport failure or a 4xx/5xx status; else return self."""
        if not self.ok:
            raise TransportError(self.error or "transport failure")
        if self.status_code >= 400:
            raise StatusError(f"HTTP {self.status_code} for {self.url}", self)
        return self

    def __repr__(self) -> str:
        if not self.ok:
            return f"<Response error={self.error!r}>"
        return (
            f"<Response [{self.status_code}] {self.alpn or '?'} "
            f"{len(self.content)} bytes>"
        )
