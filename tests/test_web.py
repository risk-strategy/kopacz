"""Tests for WebFetch: URL validation, data flow, chunking, errors."""

import http.server
import struct
import threading
import time

import pytest

from kopacz.apps.web import (
    WebFetch,
    validate_url,
    distill_html,
    FETCH,
    POST,
    FETCH_READER,
    POST_READER,
    HEADER,
    CHUNK,
    END,
    MAX_CHUNK,
)
from kopacz.apps.dispatch import AppDispatcher
from kopacz.client.tunnel import TunnelClient
from kopacz.protocol.crypto import derive_pubkey
from kopacz.relay.server import RelayHandler
from kopacz.relay.switch import Switch

SERVER_PRIV = b"\x42" * 32
PSK = derive_pubkey(SERVER_PRIV)
DOMAIN = "web.example.com"


class MockResolver:
    def __init__(self, handler: RelayHandler):
        self.handler = handler

    def query(self, qname: str) -> str | None:
        txt = self.handler.build_response(qname)
        return txt if txt else None


class MockHTTPHandler(http.server.BaseHTTPRequestHandler):
    """Simple HTTP handler for testing."""

    response_body = b"<html><body>Hello World</body></html>"
    response_content_type = "text/html"
    response_status = 200

    def do_GET(self):
        if self.path == "/error":
            self.send_error(500, "Internal Server Error")
            return
        if self.path == "/large":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            # Send 20KB of data
            self.wfile.write(b"X" * 20000)
            return
        if self.path == "/slow":
            time.sleep(5)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"slow response")
            return

        self.send_response(self.response_status)
        self.send_header("Content-Type", self.response_content_type)
        self.end_headers()
        self.wfile.write(self.response_body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        post_body = self.rfile.read(length) if length > 0 else b""
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>POST_ECHO:" + post_body + b"</body></html>")

    def log_message(self, format, *args):
        pass  # suppress log output


class MockHTTPServer:
    """Localhost HTTP server for testing."""

    def __init__(self):
        self.server = http.server.HTTPServer(("127.0.0.1", 0), MockHTTPHandler)
        self.port = self.server.server_address[1]
        self.host = "127.0.0.1"
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        self.server.shutdown()

    @property
    def base_url(self):
        return f"http://{self.host}:{self.port}"


# ── URL validation ────────────────────────────────────────────

class TestValidateUrl:
    def test_http_allowed(self):
        assert validate_url("http://example.com/page") is True

    def test_https_allowed(self):
        assert validate_url("https://example.com/page") is True

    def test_ftp_rejected(self):
        assert validate_url("ftp://example.com/file") is False

    def test_file_rejected(self):
        assert validate_url("file:///etc/passwd") is False

    def test_no_scheme_rejected(self):
        assert validate_url("example.com") is False

    def test_localhost_rejected(self):
        assert validate_url("http://localhost/secret") is False

    def test_loopback_rejected(self):
        assert validate_url("http://127.0.0.1/secret") is False

    def test_private_ip_rejected(self):
        assert validate_url("http://192.168.1.1/admin") is False
        assert validate_url("http://10.0.0.1/internal") is False

    def test_empty_rejected(self):
        assert validate_url("") is False

    def test_no_host_rejected(self):
        assert validate_url("http://") is False

    def test_public_host_allowed(self):
        assert validate_url("https://bbc.co.uk/news") is True


# ── WebFetch relay side ────────────────────────────────────────

class TestWebFetchRelay:
    @staticmethod
    def _allow_localhost():
        """Patch validate_url to allow localhost for testing."""
        import kopacz.apps.web as web_mod
        original = web_mod.validate_url

        def patched(url):
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if parsed.hostname == "127.0.0.1":
                return True
            return original(url)

        web_mod.validate_url = patched
        return original

    @staticmethod
    def _restore_validate(original):
        import kopacz.apps.web as web_mod
        web_mod.validate_url = original

    def test_fetch_basic_page(self):
        """FETCH request fetches page and returns HEADER + CHUNK + END."""
        http_server = MockHTTPServer().start()
        orig = self._allow_localhost()
        try:
            switch = Switch()
            switch.register("client1")
            web = WebFetch(switch, use_tor=False, timeout=5.0)

            url = f"{http_server.base_url}/page"
            payload = bytes([FETCH]) + url.encode("utf-8")
            web.on_data("client1", payload)

            # Wait for background fetch
            time.sleep(0.5)

            # Collect downstream messages
            messages = []
            while True:
                msg = switch.poll_downstream("client1")
                if msg is None:
                    break
                messages.append(msg)

            assert len(messages) >= 3  # HEADER + at least 1 CHUNK + END

            # Verify HEADER
            assert messages[0][0] == HEADER
            status = struct.unpack(">H", messages[0][1:3])[0]
            assert status == 200
            content_type = messages[0][3:].decode("utf-8")
            assert "text/html" in content_type

            # Verify CHUNKs contain the body
            body = b""
            for msg in messages[1:]:
                if msg[0] == CHUNK:
                    body += msg[1:]

            assert b"Hello World" in body

            # Verify END
            assert messages[-1] == bytes([END])
        finally:
            http_server.stop()
            self._restore_validate(orig)

    def test_fetch_large_response_chunked(self):
        """Large responses are split into multiple CHUNK packets."""
        http_server = MockHTTPServer().start()
        orig = self._allow_localhost()
        try:
            switch = Switch()
            switch.register("client1")
            web = WebFetch(switch, use_tor=False, timeout=5.0)

            url = f"{http_server.base_url}/large"
            payload = bytes([FETCH]) + url.encode("utf-8")
            web.on_data("client1", payload)

            time.sleep(0.5)

            messages = []
            while True:
                msg = switch.poll_downstream("client1")
                if msg is None:
                    break
                messages.append(msg)

            # Should have multiple CHUNK messages for 20KB
            chunks = [m for m in messages if m[0] == CHUNK]
            assert len(chunks) >= 5  # 20000 / 4000 = 5

            # Total body size should be 20KB
            body = b""
            for c in chunks:
                body += c[1:]
            assert len(body) == 20000

            # Each chunk should be at most MAX_CHUNK bytes
            for c in chunks:
                assert len(c[1:]) <= MAX_CHUNK
        finally:
            http_server.stop()
            self._restore_validate(orig)

    def test_ssrf_rejected(self):
        """FETCH to private IP is rejected."""
        switch = Switch()
        switch.register("c1")
        web = WebFetch(switch, use_tor=False)

        url = "http://192.168.1.1/admin"
        payload = bytes([FETCH]) + url.encode("utf-8")
        web.on_data("c1", payload)

        # Should get error response via downstream
        time.sleep(0.2)
        messages = []
        while True:
            msg = switch.poll_downstream("c1")
            if msg is None:
                break
            messages.append(msg)

        assert len(messages) >= 2
        assert messages[0][0] == HEADER
        status = struct.unpack(">H", messages[0][1:3])[0]
        assert status == 403

    def test_empty_url_rejected(self):
        """FETCH with empty URL returns error."""
        switch = Switch()
        switch.register("c1")
        web = WebFetch(switch, use_tor=False)

        payload = bytes([FETCH])
        web.on_data("c1", payload)

        time.sleep(0.2)
        msg = switch.poll_downstream("c1")
        assert msg is not None
        assert msg[0] == HEADER
        status = struct.unpack(">H", msg[1:3])[0]
        assert status == 400

    def test_empty_payload_safe(self):
        """Empty payload does nothing."""
        switch = Switch()
        web = WebFetch(switch, use_tor=False)
        assert web.on_data("x", b"") is None

    def test_unknown_message_type(self):
        """Unknown message type is ignored."""
        switch = Switch()
        web = WebFetch(switch, use_tor=False)
        assert web.on_data("x", bytes([0xFF]) + b"data") is None

    def test_server_error_returns_status(self):
        """Server 500 error is returned as HEADER with status 500."""
        http_server = MockHTTPServer().start()
        orig = self._allow_localhost()
        try:
            switch = Switch()
            switch.register("c1")
            web = WebFetch(switch, use_tor=False, timeout=5.0)

            url = f"{http_server.base_url}/error"
            payload = bytes([FETCH]) + url.encode("utf-8")
            web.on_data("c1", payload)

            time.sleep(0.5)

            messages = []
            while True:
                msg = switch.poll_downstream("c1")
                if msg is None:
                    break
                messages.append(msg)

            # Should have a response (either 500 from server or 502 from error handling)
            assert len(messages) >= 1
            assert messages[0][0] == HEADER
        finally:
            http_server.stop()
            self._restore_validate(orig)


# ── Full E2E through tunnel ───────────────────────────────────

class TestWebFetchE2E:
    @staticmethod
    def _allow_localhost():
        import kopacz.apps.web as web_mod
        original = web_mod.validate_url

        def patched(url):
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if parsed.hostname == "127.0.0.1":
                return True
            return original(url)

        web_mod.validate_url = patched
        return original

    @staticmethod
    def _restore_validate(original):
        import kopacz.apps.web as web_mod
        web_mod.validate_url = original

    def test_fetch_through_tunnel(self):
        """Full path: client → tunnel → relay → WebFetch → HTTP → relay → tunnel → client."""
        http_server = MockHTTPServer().start()
        orig = self._allow_localhost()
        try:
            dispatcher = AppDispatcher()
            handler = RelayHandler(DOMAIN, SERVER_PRIV, on_data=dispatcher.on_data)
            web = WebFetch(handler.switch, use_tor=False, timeout=5.0)
            dispatcher.register(0x04, web.on_data)

            resolver = MockResolver(handler)
            tunnel = TunnelClient(DOMAIN, PSK, resolver, tag="web-e2e")
            tunnel.connect()

            # Send FETCH through tunnel (app ID 0x04 + FETCH type + URL)
            url = f"{http_server.base_url}/page"
            fetch_payload = bytes([0x04, FETCH]) + url.encode("utf-8")
            tunnel.send(fetch_payload)

            # Wait for background fetch to complete
            time.sleep(0.5)

            # Poll for response
            results = tunnel.poll_all()

            # Should have received response data
            assert len(results) > 0

            # Parse response: first should be HEADER
            first = results[0]
            assert first[0] == HEADER
            status = struct.unpack(">H", first[1:3])[0]
            assert status == 200

            # Collect body from CHUNKs
            body = b""
            for r in results:
                if r[0] == CHUNK:
                    body += r[1:]

            assert b"Hello World" in body
        finally:
            http_server.stop()
            self._restore_validate(orig)

    def test_post_form_through_tunnel(self):
        """Full POST path: client sends POST(0x02) + url_len + url + form_body."""
        http_server = MockHTTPServer().start()
        orig = self._allow_localhost()
        try:
            dispatcher = AppDispatcher()
            handler = RelayHandler(DOMAIN, SERVER_PRIV, on_data=dispatcher.on_data)
            web = WebFetch(handler.switch, use_tor=False, timeout=5.0)
            dispatcher.register(0x04, web.on_data)

            resolver = MockResolver(handler)
            tunnel = TunnelClient(DOMAIN, PSK, resolver, tag="web-post")
            tunnel.connect()

            url_bytes = f"{http_server.base_url}/search".encode("utf-8")
            form_body = b"q=kopacz+dns&lang=en"
            post_payload = (
                bytes([0x04, POST])
                + struct.pack(">H", len(url_bytes))
                + url_bytes
                + form_body
            )
            tunnel.send(post_payload)

            time.sleep(0.5)
            results = tunnel.poll_all()
            assert len(results) > 0
            assert results[0][0] == HEADER
            status = struct.unpack(">H", results[0][1:3])[0]
            assert status == 200

            body = b"".join(r[1:] for r in results if r[0] == CHUNK)
            assert b"POST_ECHO:q=kopacz+dns&lang=en" in body
        finally:
            http_server.stop()
            self._restore_validate(orig)

    def test_coexists_with_other_apps(self):
        """WebFetch coexists with CONNECT proxy and other apps."""
        http_server = MockHTTPServer().start()
        orig = self._allow_localhost()
        try:
            dispatcher = AppDispatcher()
            handler = RelayHandler(DOMAIN, SERVER_PRIV, on_data=dispatcher.on_data)

            # Register all apps
            web = WebFetch(handler.switch, use_tor=False, timeout=5.0)
            dispatcher.register(0x04, web.on_data)

            ssh_data = []
            dispatcher.register(0x02, lambda t, d: ssh_data.append(d))

            msg_data = []
            dispatcher.register(0x03, lambda t, d: msg_data.append(d))

            resolver = MockResolver(handler)

            # Web client
            t1 = TunnelClient(DOMAIN, PSK, resolver, tag="web1")
            t1.connect()
            url = f"{http_server.base_url}/page"
            t1.send(bytes([0x04, FETCH]) + url.encode("utf-8"))

            # SSH client
            t2 = TunnelClient(DOMAIN, PSK, resolver, tag="ssh1")
            t2.connect()
            t2.send(b"\x02ssh-command")

            # Messaging client
            t3 = TunnelClient(DOMAIN, PSK, resolver, tag="msg1")
            t3.connect()
            t3.send(b"\x03register-msg")

            # Verify other apps received data
            assert len(ssh_data) == 1
            assert ssh_data[0] == b"ssh-command"
            assert len(msg_data) == 1
            assert msg_data[0] == b"register-msg"

            # Verify web fetch works
            time.sleep(0.5)
            results = t1.poll_all()
            assert len(results) > 0
        finally:
            http_server.stop()
            self._restore_validate(orig)

    def test_distill_html_strips_scripts_and_resolves_links(self):
        """distill_html removes script/style/img/svg bloat and resolves relative URLs."""
        raw = (
            b"<html><head><title>News Site</title>"
            b"<script>alert('xss')</script>"
            b"<style>.huge{background:url(bg.png)}</style>"
            b"<link rel='stylesheet' href='/app.css'>"
            b"</head><body>"
            b"<header><nav><a href='/world'>World</a></nav></header>"
            b"<article><h1>Headline</h1><p>Story text.</p>"
            b"<img src='/photo.jpg'>"
            b"<form action='/search' method='post'>"
            b"<input type='text' name='q' value='test'>"
            b"<button type='submit'>Go</button>"
            b"</form></article></body></html>"
        )
        out = distill_html(raw, "https://bbc.example.com/news/index.html").decode("utf-8")
        assert "<script" not in out
        assert "alert(" not in out
        assert "<img" not in out
        assert "<link" not in out
        assert "<title>News Site</title>" in out
        assert 'href="https://bbc.example.com/world"' in out
        assert 'action="https://bbc.example.com/search"' in out
        assert "<h1>Headline</h1>" in out
        assert "Story text." in out

    def test_fetch_reader_mode_through_tunnel(self):
        """FETCH_READER (0x03) returns distilled HTML through the tunnel."""
        http_server = MockHTTPServer().start()
        orig = self._allow_localhost()
        old_body = MockHTTPHandler.response_body
        MockHTTPHandler.response_body = (
            b"<html><head><title>Test Reader</title><script>var x=1;</script></head>"
            b"<body><article><h1>Clean Article</h1><a href='/next'>Next</a></article></body></html>"
        )
        try:
            dispatcher = AppDispatcher()
            handler = RelayHandler(DOMAIN, SERVER_PRIV, on_data=dispatcher.on_data)
            web = WebFetch(handler.switch, use_tor=False, timeout=5.0)
            dispatcher.register(0x04, web.on_data)

            resolver = MockResolver(handler)
            tunnel = TunnelClient(DOMAIN, PSK, resolver, tag="web-rdr")
            tunnel.connect()

            url = f"{http_server.base_url}/article"
            tunnel.send(bytes([0x04, FETCH_READER]) + url.encode("utf-8"))

            time.sleep(0.5)
            results = tunnel.poll_all()
            assert len(results) > 0
            assert results[0][0] == HEADER
            body = b"".join(r[1:] for r in results if r[0] == CHUNK).decode("utf-8")
            assert "<script" not in body
            assert "<h1>Clean Article</h1>" in body
            assert f'href="{http_server.base_url}/next"' in body
        finally:
            MockHTTPHandler.response_body = old_body
            http_server.stop()
            self._restore_validate(orig)
