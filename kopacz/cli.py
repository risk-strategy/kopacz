"""
Kopacz Client CLI — unified command-line interface for all Kopacz v3 client applications.

Subcommands:
    kopacz-client socks   — Run local SOCKS5 proxy (0x01 CONNECT proxy)
    kopacz-client ssh     — Run stdio tunnel for SSH ProxyCommand (0x02 TCP bridge)
    kopacz-client chat    — Register, send, or poll E2E dead-drop messages (0x03 Messaging)
    kopacz-client fetch   — Fetch URL (raw or relay-distilled reader mode) over DNS (0x04 Web)
"""

from __future__ import annotations

import argparse
import os
import select
import struct
import sys
import time
from typing import Optional

from .client.tunnel import TunnelClient, UDPResolver
from .protocol.crypto import derive_pubkey, generate_keypair
from .apps.clients.proxy import LocalProxy
from .apps.clients.ssh import SSHClient
from .apps.clients.chat import MessageClient
from .apps.messaging import E2ECrypto
from .apps.web import FETCH, POST, FETCH_READER, POST_READER, HEADER, CHUNK, END


def _build_tunnel(args: argparse.Namespace, tag: Optional[str] = None) -> TunnelClient:
    pub_hex = (
        args.pubkey
        or args.psk
        or os.environ.get("KOPACZ_PUBKEY")
        or os.environ.get("KOPACZ_PSK", "")
    ).strip()
    if len(pub_hex) != 64 or pub_hex == "0" * 64:
        raise SystemExit("Error: 64-character hex server public key required (--pubkey / -k or KOPACZ_PUBKEY)")
    server_pub = bytes.fromhex(pub_hex)
    domain = (args.domain or os.environ.get("KOPACZ_DOMAIN", "")).strip()
    if not domain:
        raise SystemExit("Error: Tunnel domain required (--domain or KOPACZ_DOMAIN)")
    ns_host, _, ns_port_s = args.resolver.partition(":")
    ns_port = int(ns_port_s) if ns_port_s else 53
    resolver = UDPResolver(nameserver=ns_host, port=ns_port, timeout=args.timeout)
    return TunnelClient(
        domain=domain,
        psk=server_pub,
        resolver=resolver,
        tag=tag or args.tag,
        posture=args.posture,
    )


def _cmd_socks(args: argparse.Namespace) -> int:
    bind_host, _, bind_port_s = args.bind.partition(":")
    bind_port = int(bind_port_s) if bind_port_s else 1080
    proxy = LocalProxy(
        tunnel_factory=lambda: _build_tunnel(args),
        bind=bind_host or "127.0.0.1",
        port=bind_port,
    )
    print(f"Kopacz SOCKS5 proxy listening on {bind_host or '127.0.0.1'}:{bind_port} (posture={args.posture})", file=sys.stderr)
    try:
        proxy.run()
    except KeyboardInterrupt:
        proxy.stop()
    return 0


def _cmd_ssh(args: argparse.Namespace) -> int:
    tunnel = _build_tunnel(args, tag=args.tag or "bridge")
    tunnel.connect()
    ssh = SSHClient(tunnel)
    stdin_fd = sys.stdin.fileno()
    stdout_fd = sys.stdout.fileno()
    idle = 0.02
    try:
        while True:
            rlist, _, _ = select.select([stdin_fd], [], [], idle)
            if rlist:
                chunk = os.read(stdin_fd, 2048)
                if not chunk:
                    break
                for down in ssh.send(chunk):
                    os.write(stdout_fd, down)
                idle = 0.01
            else:
                down_list = ssh.poll_all(max_polls=8)
                for down in down_list:
                    os.write(stdout_fd, down)
                idle = 0.01 if down_list else min(0.25, idle * 1.5)
    except KeyboardInterrupt:
        pass
    finally:
        tunnel.close()
    return 0


def _cmd_fetch(args: argparse.Namespace) -> int:
    tunnel = _build_tunnel(args)
    tunnel.connect()
    try:
        url_bytes = args.url.encode("utf-8")
        if args.data is not None:
            body_bytes = args.data.encode("utf-8")
            op = POST_READER if args.reader else POST
            payload = (
                bytes([0x04, op])
                + struct.pack(">H", len(url_bytes))
                + url_bytes
                + body_bytes
            )
        else:
            op = FETCH_READER if args.reader else FETCH
            payload = bytes([0x04, op]) + url_bytes

        chunks = list(tunnel.send(payload))
        deadline = time.monotonic() + args.timeout * 6
        done = False
        body = bytearray()
        status = 0

        def _consume(msgs: list[bytes]) -> None:
            nonlocal done, status
            for m in msgs:
                if not m:
                    continue
                if m[0] == HEADER and len(m) >= 3:
                    status = struct.unpack(">H", m[1:3])[0]
                elif m[0] == CHUNK and len(m) > 1:
                    body.extend(m[1:])
                elif m[0] == END:
                    done = True

        _consume(chunks)
        while not done and time.monotonic() < deadline:
            polled = tunnel.poll_all(max_polls=64, retry_delay=0.25, max_empty=4)
            _consume(polled)
            if not polled and not done:
                time.sleep(0.2)

        sys.stdout.buffer.write(bytes(body))
        sys.stdout.buffer.flush()
        return 0 if (200 <= status < 400 or body) else 1
    finally:
        tunnel.close()


def _cmd_chat(args: argparse.Namespace) -> int:
    crypto = E2ECrypto.from_private_bytes(bytes.fromhex(args.key)) if args.key else E2ECrypto()
    if args.keygen:
        print(f"PRIVATE_KEY={crypto.private_key_bytes.hex()}")
        print(f"PUBLIC_KEY={crypto.public_key_bytes.hex()}")
        return 0

    tunnel = _build_tunnel(args)
    tunnel.connect()
    try:
        client = MessageClient(tunnel, handle=args.handle, crypto=crypto)
        client.register()
        if args.to and args.message:
            if not args.peer_key or len(args.peer_key) != 64:
                raise SystemExit("Error: --peer-key (64 hex chars) required to send E2E message")
            client.send_message(args.to, args.message.encode("utf-8"), bytes.fromhex(args.peer_key))
            print(f"Sent E2E message to {args.to} (our pubkey: {crypto.public_key_bytes.hex()})", file=sys.stderr)
        for sender, pt in client.receive_messages():
            print(f"[{sender}] {pt.decode('utf-8', errors='replace')}")
        return 0
    finally:
        tunnel.close()


def _cmd_echo(args: argparse.Namespace) -> int:
    tunnel = _build_tunnel(args)
    tunnel.connect()
    try:
        raw = sys.stdin.buffer.read()
        for off in range(0, len(raw), 4096):
            chunk = raw[off : off + 4096]
            down = list(tunnel.send(chunk))
            got = 0
            for d in down:
                sys.stdout.buffer.write(d)
                got += len(d)
            while got < len(chunk):
                polled = tunnel.poll_all(max_polls=32, retry_delay=0.02, max_empty=2)
                for p in polled:
                    sys.stdout.buffer.write(p)
                    got += len(p)
        sys.stdout.buffer.flush()
        return 0
    finally:
        tunnel.close()


def _cmd_keygen(args: argparse.Namespace) -> int:
    if args.priv:
        priv = bytes.fromhex(args.priv.strip())
        pub = derive_pubkey(priv)
    else:
        priv, pub = generate_keypair()
    print(f"KOPACZ_PRIVKEY={priv.hex()}")
    print(f"KOPACZ_PUBKEY={pub.hex()}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="kopacz-client", description="Kopacz v3 DNS tunnel client")
    parser.add_argument("--domain", "-d", help="Tunnel domain (or KOPACZ_DOMAIN)")
    parser.add_argument("--pubkey", "-k", help="64-char hex server public key (or KOPACZ_PUBKEY)")
    parser.add_argument("--psk", help=argparse.SUPPRESS)
    parser.add_argument("--resolver", "-r", default=os.environ.get("KOPACZ_RESOLVER", "1.1.1.1:53"), help="DNS resolver host[:port] (default: 1.1.1.1:53)")
    parser.add_argument("--posture", "-p", default=os.environ.get("KOPACZ_POSTURE", "balanced"), choices=["turbo", "balanced", "covert"], help="Transport posture")
    parser.add_argument("--tag", "-t", help="Optional session tag")
    parser.add_argument("--timeout", type=float, default=5.0, help="DNS query timeout in seconds")

    sub = parser.add_subparsers(dest="cmd", required=True)

    p_keygen = sub.add_parser("keygen", help="Generate relay static X25519 keypair (or derive pubkey from --priv)")
    p_keygen.add_argument("--priv", help="Optional 64-char hex private key to derive public key from")

    p_socks = sub.add_parser("socks", help="Start local SOCKS5 proxy over DNS")
    p_socks.add_argument("--bind", "-b", default="127.0.0.1:1080", help="Bind address:port (default: 127.0.0.1:1080)")

    sub.add_parser("ssh", help="Stdio TCP bridge forwarder for ssh -o ProxyCommand")
    sub.add_parser("echo", help="Send stdin over tunnel and write echoed downstream data to stdout")

    p_fetch = sub.add_parser("fetch", help="Fetch URL through tunnel (0x04 WebFetch)")
    p_fetch.add_argument("url", help="Target HTTP/HTTPS URL")
    p_fetch.add_argument("--reader", action="store_true", help="Use relay-side DOM distillation (Reader mode)")
    p_fetch.add_argument("--data", help="Optional POST form body")

    p_chat = sub.add_parser("chat", help="E2E dead-drop messaging client (0x03)")
    p_chat.add_argument("--handle", default="anon", help="Your 1..16 byte handle")
    p_chat.add_argument("--key", help="Your 64-hex-char X25519 private key")
    p_chat.add_argument("--keygen", action="store_true", help="Generate and print an X25519 keypair")
    p_chat.add_argument("--to", help="Recipient handle")
    p_chat.add_argument("--peer-key", help="Recipient 64-hex-char X25519 public key")
    p_chat.add_argument("--message", "-m", help="Message text to send")

    args = parser.parse_args(argv)
    if args.cmd == "keygen":
        return _cmd_keygen(args)
    if args.cmd == "socks":
        return _cmd_socks(args)
    if args.cmd == "ssh":
        return _cmd_ssh(args)
    if args.cmd == "echo":
        return _cmd_echo(args)
    if args.cmd == "fetch":
        return _cmd_fetch(args)
    if args.cmd == "chat":
        return _cmd_chat(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
