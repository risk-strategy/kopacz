"""Tests for AppDispatcher."""

from kopacz.apps.dispatch import AppDispatcher


class TestRouting:
    def test_routes_to_registered_handler(self):
        d = AppDispatcher()
        received = []
        d.register(0x01, lambda tag, data: received.append((tag, data)))
        d.on_data("alice", b"\x01hello")
        assert received == [("alice", b"hello")]

    def test_strips_app_id_byte(self):
        d = AppDispatcher()
        payloads = []
        d.register(0x02, lambda tag, data: payloads.append(data))
        d.on_data("bob", b"\x02\xde\xad")
        assert payloads == [b"\xde\xad"]

    def test_multiple_handlers(self):
        d = AppDispatcher()
        h1, h2 = [], []
        d.register(0x01, lambda t, d: h1.append(d))
        d.register(0x02, lambda t, d: h2.append(d))

        d.on_data("x", b"\x01aaa")
        d.on_data("y", b"\x02bbb")

        assert h1 == [b"aaa"]
        assert h2 == [b"bbb"]

    def test_handler_return_value_propagated(self):
        d = AppDispatcher()
        d.register(0x01, lambda t, d: b"response")
        result = d.on_data("x", b"\x01payload")
        assert result == b"response"

    def test_handler_return_none(self):
        d = AppDispatcher()
        d.register(0x01, lambda t, d: None)
        result = d.on_data("x", b"\x01payload")
        assert result is None

    def test_tag_forwarded(self):
        d = AppDispatcher()
        tags = []
        d.register(0x03, lambda tag, data: tags.append(tag))
        d.on_data("session-42", b"\x03data")
        assert tags == ["session-42"]


class TestUnknownAndEdge:
    def test_unknown_id_returns_none(self):
        d = AppDispatcher()
        assert d.on_data("x", b"\xff" + b"data") is None

    def test_no_handlers_returns_none(self):
        d = AppDispatcher()
        assert d.on_data("x", b"\x01data") is None

    def test_empty_data_returns_none(self):
        d = AppDispatcher()
        d.register(0x01, lambda t, d: b"should not happen")
        assert d.on_data("x", b"") is None

    def test_single_byte_routes_with_empty_payload(self):
        d = AppDispatcher()
        payloads = []
        d.register(0x01, lambda t, d: payloads.append(d))
        d.on_data("x", b"\x01")
        assert payloads == [b""]

    def test_replace_handler(self):
        d = AppDispatcher()
        d.register(0x01, lambda t, d: b"first")
        d.register(0x01, lambda t, d: b"second")
        assert d.on_data("x", b"\x01x") == b"second"
