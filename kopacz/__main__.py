"""
CLI entry point for the Kopacz relay server.

Usage:
    python -m kopacz --config /etc/kopacz/relay.toml

Environment variable overrides (useful for Docker):
    TOR_HOST  — override [tor].host
    TOR_PORT  — override [tor].port
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]

from .protocol.crypto import derive_pubkey, generate_keypair
from .relay.server import RelayHandler, RelayServer
from .apps.dispatch import AppDispatcher
from .apps.proxy import ConnectProxy
from .apps.bridge import TCPBridge
from .apps.messaging import MessageRelay
from .apps.web import WebFetch
from .transport.encoding import Base32Encoder, Base36Encoder, Base64Encoder

ENCODERS = {
    "base32": Base32Encoder,
    "base64": Base64Encoder,
    "base36": Base36Encoder,
}


def load_config(path: str) -> dict:
    """Load and return parsed TOML config."""
    with open(path, "rb") as f:
        return tomllib.load(f)


def _env_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="kopacz",
        description="Kopacz DNS tunnel relay server",
    )
    parser.add_argument(
        "--config", "-c",
        default=os.environ.get("KOPACZ_CONFIG", "/etc/kopacz/relay.toml"),
        help="Path to TOML configuration file (optional if KOPACZ_PRIVKEY is set in env)",
    )
    parser.add_argument(
        "--keygen",
        action="store_true",
        help="Generate a new static X25519 keypair (relay private key + client public key) and exit",
    )
    args = parser.parse_args(argv)

    if args.keygen:
        priv, pub = generate_keypair()
        print(f"KOPACZ_PRIVKEY={priv.hex()}")
        print(f"KOPACZ_PUBKEY={pub.hex()}")
        return

    cfg: dict = {}
    if args.config and Path(args.config).is_file():
        cfg = load_config(args.config)

    # -- Logging ----------------------------------------------------------
    log_cfg = cfg.get("logging", {})
    level = os.environ.get("KOPACZ_LOG_LEVEL", log_cfg.get("level", "INFO")).upper()
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s  %(message)s",
    )
    log = logging.getLogger("kopacz")

    # -- Relay core -------------------------------------------------------
    relay_cfg = cfg.get("relay", {})
    domain = os.environ.get("KOPACZ_DOMAIN", relay_cfg.get("domain", "t.example.com"))
    priv_hex = (
        os.environ.get("KOPACZ_PRIVKEY")
        or os.environ.get("KOPACZ_PSK")
        or relay_cfg.get("privkey")
        or relay_cfg.get("psk", "")
    ).strip()
    if len(priv_hex) != 64 or priv_hex == "0" * 64:
        log.error("Relay private key must be a non-zero 64-character hex string (32 bytes); set KOPACZ_PRIVKEY or [relay].privkey")
        sys.exit(1)
    psk = bytes.fromhex(priv_hex)
    pub_hex = derive_pubkey(psk).hex()
    log.info("Relay static public key (for clients): %s", pub_hex)

    bind = os.environ.get("KOPACZ_BIND", relay_cfg.get("bind", "0.0.0.0"))
    port = int(os.environ.get("KOPACZ_PORT", relay_cfg.get("port", 53)))
    max_frag_payload = int(
        os.environ.get("KOPACZ_MAX_FRAG_PAYLOAD", relay_cfg.get("max_frag_payload", 120))
    )

    encoder_name = os.environ.get("KOPACZ_ENCODER", relay_cfg.get("encoder", "base32"))
    encoder_cls = ENCODERS.get(encoder_name)
    if encoder_cls is None:
        log.error("Unknown encoder %r (choose: %s)", encoder_name,
                  ", ".join(ENCODERS))
        sys.exit(1)
    encoder = encoder_cls()

    # -- Tor settings (env vars override config for Docker/Dokploy) -------
    tor_cfg = cfg.get("tor", {})
    tor_enabled = _env_bool("KOPACZ_TOR_ENABLED", tor_cfg.get("enabled", True))
    tor_host = os.environ.get("TOR_HOST", tor_cfg.get("host", "127.0.0.1"))
    tor_port = int(os.environ.get("TOR_PORT", tor_cfg.get("port", 9050)))

    # -- Build dispatcher + handler ---------------------------------------
    dispatcher = AppDispatcher()
    handler = RelayHandler(
        domain,
        psk,
        encoder=encoder,
        on_data=dispatcher.on_data,
        max_frag_payload=max_frag_payload,
    )
    switch = handler.switch  # apps must share the handler's switch

    # -- Apps -------------------------------------------------------------
    apps_cfg = cfg.get("apps", {})

    # 0x01 — CONNECT Proxy (enabled by default in env-driven mode)
    proxy_cfg = apps_cfg.get("proxy", {})
    proxy_default = bool(proxy_cfg.get("enabled", True if not cfg else False))
    if _env_bool("KOPACZ_PROXY_ENABLED", proxy_default):
        proxy = ConnectProxy(
            switch,
            tor_host=tor_host,
            tor_port=tor_port,
            timeout=float(os.environ.get("KOPACZ_PROXY_TIMEOUT", proxy_cfg.get("timeout", 30.0))),
            use_tor=tor_enabled,
        )
        dispatcher.register(0x01, proxy.on_data)
        log.info("App enabled: CONNECT proxy (0x01) [tor=%s %s:%d]", tor_enabled, tor_host, tor_port)

    # 0x02 — TCP Bridge
    bridge_cfg = apps_cfg.get("bridge", {})
    if _env_bool("KOPACZ_BRIDGE_ENABLED", bool(bridge_cfg.get("enabled", False))):
        tunnel_tag = os.environ.get("KOPACZ_BRIDGE_TAG", bridge_cfg.get("tunnel_tag"))
        if not tunnel_tag:
            log.error("Bridge enabled but no tunnel_tag configured")
            sys.exit(1)
        bridge = TCPBridge(
            switch,
            tunnel_tag=tunnel_tag,
            bind=os.environ.get("KOPACZ_BRIDGE_BIND", bridge_cfg.get("bind", "0.0.0.0")),
            port=int(os.environ.get("KOPACZ_BRIDGE_PORT", bridge_cfg.get("port", 8022))),
        )
        dispatcher.register(0x02, bridge.on_tunnel_data)
        bridge.start_background()
        log.info("App enabled: TCP bridge (0x02) on %s:%d tag=%s",
                 bridge.bind, bridge.port, tunnel_tag)

    # 0x03 — Messaging (enabled by default in env-driven mode)
    msg_cfg = apps_cfg.get("messaging", {})
    msg_default = bool(msg_cfg.get("enabled", True if not cfg else False))
    if _env_bool("KOPACZ_MESSAGING_ENABLED", msg_default):
        messaging = MessageRelay(switch)
        dispatcher.register(0x03, messaging.on_data)
        log.info("App enabled: Messaging (0x03)")

    # 0x04 — Web Fetch (enabled by default in env-driven mode)
    web_cfg = apps_cfg.get("web", {})
    web_default = bool(web_cfg.get("enabled", True if not cfg else False))
    if _env_bool("KOPACZ_WEB_ENABLED", web_default):
        web = WebFetch(
            switch,
            tor_host=tor_host,
            tor_port=tor_port,
            timeout=float(os.environ.get("KOPACZ_WEB_TIMEOUT", web_cfg.get("timeout", 30.0))),
            use_tor=tor_enabled,
        )
        dispatcher.register(0x04, web.on_data)
        log.info("App enabled: Web fetch (0x04) [tor=%s %s:%d]", tor_enabled, tor_host, tor_port)

    # -- Start server -----------------------------------------------------
    log.info("Starting relay on %s:%d for domain %s (encoder=%s)",
             bind, port, domain, encoder_name)
    server = RelayServer(handler, bind=bind, port=port)
    try:
        server.run()
    except KeyboardInterrupt:
        log.info("Shutting down")


if __name__ == "__main__":
    main()
