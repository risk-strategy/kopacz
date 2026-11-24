"""
Web Fetch — relay-side HTTP fetch for browser clients.

The relay fetches the requested URL (via Tor or direct) and streams
the response back through the DNS tunnel.  This lets browser clients
(which cannot do raw TLS through a tunnel) access HTTPS content.

Wire format (after 0x04 stripped by AppDispatcher):

    FETCH        (0x01): type(1) + url (remaining bytes, UTF-8)
    POST         (0x02): type(1) + url_len(2 BE) + url + body
    FETCH_READER (0x03): type(1) + url (remaining bytes, UTF-8) — relay-distilled HTML
    POST_READER  (0x04): type(1) + url_len(2 BE) + url + body   — relay-distilled HTML

Response (chunked downstream via Switch):

    HEADER (0x01): type(1) + status(2 BE) + content_type (remaining, UTF-8)
    CHUNK  (0x02): type(1) + chunk_data
    END    (0x03): type(1)
"""

from __future__ import annotations

from html.parser import HTMLParser
import logging
import re
import struct
import threading
from typing import Optional
from urllib.parse import urljoin, urlparse

from ..relay.switch import Switch

log = logging.getLogger(__name__)

# Request types
FETCH = 0x01
POST = 0x02
FETCH_READER = 0x03
POST_READER = 0x04

# Response types
HEADER = 0x01
CHUNK = 0x02
END = 0x03

MAX_CHUNK = 4000
MAX_RESPONSE_BYTES = 4 * 1024 * 1024  # 4 MB hard ceiling per fetched response
MAX_READER_BYTES = 96 * 1024          # 96 KB ceiling for distilled reader HTML
MAX_URL_LENGTH = 2048
MAX_POST_BODY_BYTES = 65536


_STRIP_SUBTREE_TAGS = frozenset({
    "script", "style", "noscript", "svg", "canvas", "iframe", "object",
    "embed", "audio", "video", "source", "picture", "img", "link", "meta",
    "template", "Slot", "slot",
})

_ALLOWED_TAGS = frozenset({
    "html", "head", "title", "body", "main", "article", "section", "header",
    "footer", "nav", "aside", "div", "p", "h1", "h2", "h3", "h4", "h5", "h6",
    "ul", "ol", "li", "dl", "dt", "dd", "blockquote", "pre", "code", "a",
    "em", "strong", "b", "i", "u", "s", "small", "sub", "sup", "mark", "span",
    "br", "hr", "table", "thead", "tbody", "tfoot", "tr", "th", "td", "caption",
    "form", "label", "input", "button", "select", "option", "textarea",
    "fieldset", "legend", "details", "summary", "figure", "figcaption", "time",
})

_VOID_TAGS = frozenset({"br", "hr", "input"})

_ALLOWED_ATTRS = {
    "a": frozenset({"href", "title"}),
    "form": frozenset({"action", "method"}),
    "input": frozenset({"type", "name", "value", "placeholder", "checked", "disabled", "readonly"}),
    "button": frozenset({"type", "name", "value", "formaction", "formmethod", "disabled"}),
    "select": frozenset({"name", "multiple", "disabled"}),
    "option": frozenset({"value", "selected"}),
    "textarea": frozenset({"name", "placeholder", "rows", "cols", "disabled", "readonly"}),
    "td": frozenset({"colspan", "rowspan"}),
    "th": frozenset({"colspan", "rowspan"}),
    "time": frozenset({"datetime"}),
    "details": frozenset({"open"}),
}

_READER_BASE_CSS = (
    "<style>"
    ":root{color-scheme:light dark}"
    "body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;"
    "line-height:1.6;max-width:54rem;margin:0 auto;padding:1.25rem 1.5rem;"
    "color:#18181b;background:#fafafa;word-wrap:break-word}"
    "@media(prefers-color-scheme:dark){body{color:#e4e4e7;background:#0c0c0e}"
    "a{color:#60a5fa}pre,code,input,select,textarea,button{background:#18181b;color:#e4e4e7;border-color:#3f3f46}"
    "th,td{border-color:#27272a}blockquote{border-color:#3f3f46;color:#a1a1aa}}"
    "h1,h2,h3,h4{line-height:1.25;margin:1.2em 0 .45em}"
    "p,ul,ol,dl,blockquote,pre,table,form{margin:.75em 0}"
    "a{color:#2563eb;text-decoration:underline;text-underline-offset:2px}"
    "pre,code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.9em;"
    "background:#f1f5f9;border-radius:4px}"
    "code{padding:.15em .35em}pre{padding:.85rem;overflow-x:auto}"
    "pre code{padding:0;background:none}"
    "blockquote{border-left:3px solid #cbd5e1;padding-left:1rem;color:#475569}"
    "table{border-collapse:collapse;width:100%}th,td{border:1px solid #e2e8f0;padding:.45rem .65rem;text-align:left}"
    "input,select,textarea,button{font:inherit;padding:.4rem .65rem;border:1px solid #cbd5e1;border-radius:4px;margin:.15rem}"
    "button,input[type=submit]{cursor:pointer;font-weight:600}"
    "nav ul,header ul{padding-left:1.2rem}"
    "hr{border:none;border-top:1px solid #e2e8f0;margin:1.5rem 0}"
    "</style>"
)


def _esc_html(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


class _ReaderDistiller(HTMLParser):
    """Distills arbitrary HTML into a compact, self-contained semantic document."""

    def __init__(self, base_url: str, max_bytes: int = MAX_READER_BYTES):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.max_bytes = max_bytes
        self._skip_depth = 0
        self._in_title = False
        self.title_parts: list[str] = []
        self.chunks: list[str] = []
        self._size = 0

    def _emit(self, text: str) -> None:
        if self._size >= self.max_bytes:
            return
        self.chunks.append(text)
        self._size += len(text)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        t = tag.lower()
        if self._skip_depth > 0:
            if t in _STRIP_SUBTREE_TAGS and t not in ("img", "link", "meta", "source"):
                self._skip_depth += 1
            return
        if t in _STRIP_SUBTREE_TAGS:
            if t not in ("img", "link", "meta", "source"):
                self._skip_depth = 1
            return
        if t == "title":
            self._in_title = True
            return
        if t in ("html", "head", "body"):
            return
        if t not in _ALLOWED_TAGS:
            return

        allowed = _ALLOWED_ATTRS.get(t)
        attr_parts: list[str] = []
        if allowed:
            for k, v in attrs:
                kl = k.lower()
                if kl not in allowed:
                    continue
                val = v or ""
                if t == "input" and kl == "type" and val.lower() in ("image", "file", "hidden"):
                    if val.lower() == "image":
                        val = "submit"
                    elif val.lower() == "file":
                        continue
                if kl in ("href", "action", "formaction") and val:
                    val = val.strip()
                    if val.lower().startswith(("javascript:", "data:", "vbscript:")):
                        continue
                    try:
                        val = urljoin(self.base_url, val)
                    except Exception:
                        pass
                if v is None or kl in ("checked", "disabled", "readonly", "multiple", "selected", "open"):
                    attr_parts.append(f" {kl}")
                else:
                    attr_parts.append(f' {kl}="{_esc_html(val)}"')

        self._emit(f"<{t}{''.join(attr_parts)}>")

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if self._skip_depth > 0:
            if t in _STRIP_SUBTREE_TAGS and t not in ("img", "link", "meta", "source"):
                self._skip_depth -= 1
            return
        if t == "title":
            self._in_title = False
            return
        if t in ("html", "head", "body") or t in _VOID_TAGS or t in _STRIP_SUBTREE_TAGS:
            return
        if t in _ALLOWED_TAGS:
            self._emit(f"</{t}>")

    def handle_data(self, data: str) -> None:
        if self._skip_depth > 0:
            return
        if self._in_title:
            self.title_parts.append(data)
            return
        collapsed = re.sub(r"[ \t\r\f\v]+", " ", data)
        if collapsed:
            self._emit(_esc_html(collapsed))


def distill_html(raw_bytes: bytes, base_url: str, max_bytes: int = MAX_READER_BYTES) -> bytes:
    """
    Distill raw HTML into a clean, self-contained Reader document with embedded
    minimal CSS, resolved links/forms, and zero external sub-resource dependencies.
    """
    html_text = raw_bytes.decode("utf-8", errors="replace")
    parser = _ReaderDistiller(base_url=base_url, max_bytes=max_bytes)
    try:
        parser.feed(html_text)
        parser.close()
    except Exception:
        pass
    title = _esc_html(" ".join("".join(parser.title_parts).split()) or base_url)
    body_html = "".join(parser.chunks).strip()
    if not body_html:
        # Fallback if page had no recognizable body tags
        stripped = re.sub(r"<[^>]+>", " ", html_text)
        body_html = f"<p>{_esc_html(' '.join(stripped.split())[:max_bytes])}</p>"
    doc = (
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
        f"<title>{title}</title>{_READER_BASE_CSS}</head>"
        f"<body>{body_html}</body></html>"
    )
    return doc.encode("utf-8")


def validate_url(url: str) -> bool:
    """Reject invalid or SSRF-targeted URLs."""
    if not url or len(url) > MAX_URL_LENGTH:
        return False
    if any(c.isspace() or ord(c) < 0x21 for c in url):
        return False
    try:
        parsed = urlparse(url)
    except Exception:
        return False

    if parsed.scheme not in ("http", "https"):
        return False

    host = parsed.hostname
    if not host:
        return False

    # Reuse SSRF checks from proxy module
    from .proxy import validate_target

    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return False
    return validate_target(host, port)


class WebFetch:
    """
    Relay-side HTTP fetcher.

    Receives a URL via the tunnel, fetches it (optionally through Tor),
    and streams the response back as HEADER + CHUNK* + END packets.
    """

    def __init__(
        self,
        switch: Switch,
        tor_host: str = "127.0.0.1",
        tor_port: int = 9050,
        timeout: float = 30.0,
        use_tor: bool = True,
        max_concurrent: int = 16,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
    ):
        self.switch = switch
        self._tor_host = tor_host
        self._tor_port = tor_port
        self._timeout = timeout
        self._use_tor = use_tor
        self._max_response_bytes = max_response_bytes
        self._sem = threading.BoundedSemaphore(max(1, max_concurrent))

    def on_data(self, tag: str, payload: bytes) -> Optional[bytes]:
        """Dispatcher callback. Payload has 0x04 prefix stripped."""
        if not payload:
            return None

        msg_type = payload[0]
        if msg_type == FETCH:
            return self._handle_fetch(tag, payload[1:], reader=False)
        if msg_type == FETCH_READER:
            return self._handle_fetch(tag, payload[1:], reader=True)
        if msg_type == POST:
            return self._handle_post(tag, payload[1:], reader=False)
        if msg_type == POST_READER:
            return self._handle_post(tag, payload[1:], reader=True)

        return None

    def _handle_fetch(self, tag: str, payload: bytes, reader: bool = False) -> Optional[bytes]:
        """Process FETCH (GET) request, stream response back."""
        if not payload:
            return self._error_response(tag, 400, "Empty URL")

        try:
            url = payload.decode("utf-8")
        except UnicodeDecodeError:
            return self._error_response(tag, 400, "Invalid URL encoding")

        if not validate_url(url):
            return self._error_response(tag, 403, "URL not allowed")

        if not self._sem.acquire(blocking=False):
            return self._error_response(tag, 429, "Too many concurrent fetches")

        # Fetch in background thread to avoid blocking
        t = threading.Thread(
            target=self._fetch_and_stream, args=(tag, url, None, reader), daemon=True
        )
        t.start()
        return None

    def _handle_post(self, tag: str, payload: bytes, reader: bool = False) -> Optional[bytes]:
        """Process POST request: url_len(2 BE) + url + body."""
        if len(payload) < 2:
            return self._error_response(tag, 400, "Malformed POST payload")

        url_len = struct.unpack(">H", payload[:2])[0]
        if url_len == 0 or len(payload) < 2 + url_len:
            return self._error_response(tag, 400, "Invalid POST URL length")

        try:
            url = payload[2 : 2 + url_len].decode("utf-8")
        except UnicodeDecodeError:
            return self._error_response(tag, 400, "Invalid URL encoding")

        if not validate_url(url):
            return self._error_response(tag, 403, "URL not allowed")

        body = payload[2 + url_len :]
        if len(body) > MAX_POST_BODY_BYTES:
            return self._error_response(tag, 413, "POST body too large")

        if not self._sem.acquire(blocking=False):
            return self._error_response(tag, 429, "Too many concurrent fetches")

        t = threading.Thread(
            target=self._fetch_and_stream, args=(tag, url, body, reader), daemon=True
        )
        t.start()
        return None

    def _fetch_and_stream(
        self, tag: str, url: str, body: Optional[bytes] = None, reader: bool = False
    ) -> None:
        """Fetch URL and stream response chunks to switch."""
        import urllib.request
        import ssl

        try:
            opener = self._make_opener()
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
                "Accept": "text/html,application/xhtml+xml,*/*",
            }
            if body is not None:
                parsed = urlparse(url)
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                headers["Referer"] = url
                headers["Origin"] = f"{parsed.scheme}://{parsed.netloc}"

            req = urllib.request.Request(
                url,
                data=body,
                headers=headers,
                method="POST" if body is not None else "GET",
            )

            resp = opener.open(req, timeout=self._timeout)

            status = resp.status
            content_type = resp.headers.get("Content-Type", "text/html")
            final_url = getattr(resp, "url", None) or url

            # Send HEADER
            header_pkt = (
                bytes([HEADER])
                + struct.pack(">H", status)
                + content_type.encode("utf-8", errors="replace")
            )
            self.switch.enqueue_downstream(tag, header_pkt)

            if reader and "html" in content_type.lower():
                raw = resp.read(self._max_response_bytes)
                distilled = distill_html(raw, final_url)
                for offset in range(0, len(distilled), MAX_CHUNK):
                    self.switch.enqueue_downstream(
                        tag, bytes([CHUNK]) + distilled[offset : offset + MAX_CHUNK]
                    )
            else:
                # Stream CHUNK packets up to max_response_bytes
                total_read = 0
                while total_read < self._max_response_bytes:
                    to_read = min(MAX_CHUNK, self._max_response_bytes - total_read)
                    chunk = resp.read(to_read)
                    if not chunk:
                        break
                    total_read += len(chunk)
                    self.switch.enqueue_downstream(
                        tag, bytes([CHUNK]) + chunk
                    )

            # Send END
            self.switch.enqueue_downstream(tag, bytes([END]))

        except Exception as e:
            log.debug("Fetch failed for %s: %s", url, e)
            self._error_response(tag, 502, str(e))
        finally:
            self._sem.release()

    def _make_opener(self) -> urllib.request.OpenerDirector:
        """Create URL opener with redirect SSRF protection and optional Tor SOCKS5 routing."""
        import ssl
        import urllib.error
        import urllib.parse
        import urllib.request

        class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                resolved = urllib.parse.urljoin(req.full_url, newurl)
                if not validate_url(resolved):
                    raise urllib.error.HTTPError(
                        resolved, 403, "Redirect target not allowed (SSRF blocked)", headers, fp
                    )
                return super().redirect_request(req, fp, code, msg, headers, resolved)

        ctx = ssl.create_default_context()
        if self._use_tor:
            try:
                import socks
                from sockshandler import SocksiPyHandler
            except ImportError:
                raise RuntimeError(
                    "PySocks required for Tor: pip install 'kopacz[proxy]'"
                )
            opener = urllib.request.build_opener(
                _SafeRedirectHandler(),
                SocksiPyHandler(
                    socks.SOCKS5,
                    self._tor_host,
                    self._tor_port,
                    rdns=True,
                    context=ctx,
                ),
            )
        else:
            opener = urllib.request.build_opener(
                _SafeRedirectHandler(),
                urllib.request.HTTPSHandler(context=ctx),
            )
        # Strip non-HTTP handlers (FTPHandler, FileHandler, DataHandler) so a
        # redirect can never bypass Tor or access local files/FTP.
        opener.handlers = [
            h
            for h in opener.handlers
            if not isinstance(
                h,
                (
                    urllib.request.FTPHandler,
                    urllib.request.FileHandler,
                    urllib.request.DataHandler,
                ),
            )
        ]
        return opener

    def _error_response(self, tag: str, status: int, message: str) -> None:
        """Send error as HEADER + CHUNK(message) + END."""
        header_pkt = (
            bytes([HEADER])
            + struct.pack(">H", status)
            + b"text/plain"
        )
        self.switch.enqueue_downstream(tag, header_pkt)
        self.switch.enqueue_downstream(
            tag, bytes([CHUNK]) + message.encode("utf-8", errors="replace")
        )
        self.switch.enqueue_downstream(tag, bytes([END]))
        return None
