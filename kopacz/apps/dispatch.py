"""
Application dispatcher — routes upstream messages by app-ID byte.

First byte of every upstream message (after tunnel decryption) is
an app ID:

    0x01 = CONNECT Proxy
    0x02 = SSH Bridge
    0x03 = Messaging

The dispatcher strips the app-ID byte and delegates to the
registered handler.  Wired as:

    dispatcher = AppDispatcher()
    handler = RelayHandler(domain, psk, on_data=dispatcher.on_data)
"""

from __future__ import annotations

import logging
from typing import Callable, Dict, Optional

log = logging.getLogger(__name__)

AppHandler = Callable[[str, bytes], Optional[bytes]]


class AppDispatcher:
    """
    Multi-app router for RelayHandler's on_data callback.

    register(app_id, handler) — register an app handler
    on_data(tag, data)        — strips first byte, delegates
    """

    def __init__(self) -> None:
        self._handlers: Dict[int, AppHandler] = {}

    def register(self, app_id: int, handler: AppHandler) -> None:
        """Register a handler for the given app-ID byte."""
        self._handlers[app_id] = handler

    def on_data(self, tag: str, data: bytes) -> Optional[bytes]:
        """
        Strip app-ID prefix, delegate to registered handler.

        Returns handler result, or None if unknown / empty.
        """
        if not data:
            return None

        app_id = data[0]
        handler = self._handlers.get(app_id)
        if handler is None:
            log.debug("Unknown app ID 0x%02x from tag %s", app_id, tag)
            return None

        return handler(tag, data[1:])
