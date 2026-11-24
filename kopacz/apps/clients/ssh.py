"""
SSH tunnel client helper.

Thin wrapper around TunnelClient that prepends the 0x02 app-ID
byte to every upstream message.  The dispatcher on the relay side
strips the prefix before handing data to TCPBridge.

Downstream direction (TCP → tunnel) has no prefix — the client
knows it's an SSH session.
"""

from __future__ import annotations

from typing import List, Optional

from ...client.tunnel import TunnelClient


class SSHClient:
    """Tunnel-aware SSH forwarder (client side)."""

    APP_ID = 0x02

    def __init__(self, tunnel: TunnelClient):
        self.tunnel = tunnel

    def send(self, data: bytes) -> List[bytes]:
        """Send SSH data upstream with app-ID prefix."""
        return self.tunnel.send(bytes([self.APP_ID]) + data)

    def poll(self) -> Optional[bytes]:
        """Poll for downstream SSH data."""
        return self.tunnel.poll()

    def poll_all(self) -> List[bytes]:
        """Poll all pending downstream SSH data."""
        return self.tunnel.poll_all()
