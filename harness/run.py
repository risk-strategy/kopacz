#!/usr/bin/env python3
"""
Kopacz v3 Interactive Verification & Benchmark Harness.

Proves end-to-end execution, cryptographic asymmetry/PFS, byte-for-byte integrity
(SHA-256 in == SHA-256 out), DNS wire query counts, and real throughput across:
  - Python CLI client     (clients/python/kopacz_client.py)
  - Standalone C99 client (clients/c/kopacz.c -> clients/c/kopacz)
  - Bash client           (clients/bash/kopacz.sh)
  - Web Fetch / Reader    (0x04 WebFetch + local HTTP origin + DoH endpoint)
  - E2E Dead-Drop Chat    (0x03 MessageRelay)

Usage:
  ./venv/bin/python3 harness/run.py                  # Run full automated proof suite
  ./venv/bin/python3 harness/run.py --size 32768     # Custom payload size (bytes)
  ./venv/bin/python3 harness/run.py --interactive    # Interactive menu mode
"""

from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from kopacz.apps.dispatch import AppDispatcher
from kopacz.apps.messaging import E2ECrypto, MessageRelay
from kopacz.apps.clients.chat import MessageClient
from kopacz.apps.web import WebFetch, distill_html
from kopacz.client.tunnel import TunnelClient, UDPResolver
from kopacz.protocol.crypto import CryptoState, derive_pubkey, generate_keypair
from kopacz.relay.server import RelayHandler, RelayServer


@dataclass
class ProofResult:
    name: str
    client: str
    mode: str
    bytes_in: int
    bytes_out: int
    sha256_in: str
    sha256_out: str
    queries: int
    elapsed_ms: float
    kbps: float
    passed: bool
    note: str = ""


class InstrumentedRelayHandler(RelayHandler):
    """RelayHandler wrapper that counts wire DNS queries and falls back to raw echo."""

    def __init__(self, domain: str, privkey: bytes, app_on_data: Callable[[str, bytes], Optional[bytes]]):
        self.query_counter = 0
        self._app_on_data = app_on_data
        super().__init__(domain, privkey, on_data=self._route_or_echo, max_frag_payload=480)

    def _route_or_echo(self, tag: str, data: bytes) -> Optional[bytes]:
        # If first byte is a registered app ID (0x01..0x04) and tag starts with 'app',
        # or if data starts with 0x04 / 0x03 app prefix, dispatch to app; otherwise echo raw data.
        if data and data[0] in (0x03, 0x04) and tag.startswith("app"):
            return self._app_on_data(tag, data)
        return data

    def build_response(self, qname: str) -> str:
        self.query_counter += 1
        return super().build_response(qname)


class LocalTestEnvironment:
    """Spins up a real UDP DNS RelayServer, a local DoH server, and a local HTTP origin."""

    def __init__(self) -> None:
        self.domain = "t.example.com"
        self.server_priv, self.server_pub = generate_keypair()

        self.dispatcher = AppDispatcher()
        self.handler = InstrumentedRelayHandler(
            self.domain,
            self.server_priv,
            app_on_data=self.dispatcher.on_data,
        )
        self.web_app = WebFetch(self.handler.switch, use_tor=False)
        # Allow local test origin IP (127.0.0.1) inside harness by patching validate_url on web_app
        self.dispatcher.register(0x04, self._handle_web_local)
        self.msg_app = MessageRelay(self.handler.switch)
        self.dispatcher.register(0x03, self.msg_app.on_data)

        # Find ephemeral UDP port for DNS RelayServer
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind(("127.0.0.1", 0))
        self.dns_port = probe.getsockname()[1]
        probe.close()

        self.dns_server = RelayServer(self.handler, bind="127.0.0.1", port=self.dns_port)
        self._dns_thread: Optional[threading.Thread] = None

        # Local HTTP origin server for WebFetch testing
        self.http_payload = (
            "<!DOCTYPE html><html><head><title>Kopacz Harness Origin</title>"
            "<script>console.log('bloat script stripped in reader mode');</script>"
            "<style>.ad{display:none}</style></head><body>"
            "<main><h1>Kopacz Live Harness Verification</h1>"
            "<p>This article was fetched over an encrypted 1-RTT Noise_NK DNS tunnel.</p>"
            "<p>" + ("Verified payload block over DNS transport. " * 60) + "</p>"
            "<a href='/page2'>Relative Link</a></main></body></html>"
        ).encode("utf-8")
        self.http_server = self._start_http_origin()
        self.http_port = self.http_server.server_port

        # Local RFC 8484 JSON DoH server
        self.doh_server = self._start_doh_server()
        self.doh_port = self.doh_server.server_port

    def _handle_web_local(self, tag: str, data: bytes) -> Optional[bytes]:
        from unittest.mock import patch
        with patch("kopacz.apps.web.validate_url", return_value=True):
            return self.web_app.on_data(tag, data)

    def _start_http_origin(self) -> http.server.HTTPServer:
        payload = self.http_payload

        class OriginHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format, *args):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), OriginHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    def _start_doh_server(self) -> http.server.HTTPServer:
        relay_handler = self.handler

        class DoHHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                qs = urllib.parse.parse_qs(parsed.query)
                qname = qs.get("name", [""])[0]
                txt = relay_handler.build_response(qname) if qname else ""
                body = json.dumps({
                    "Status": 0,
                    "Answer": [{"name": qname, "type": 16, "TTL": 0, "data": f'"{txt}"'}] if txt else [],
                }).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/dns-json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), DoHHandler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    def start(self) -> None:
        self._dns_thread = threading.Thread(target=self.dns_server.run, daemon=True)
        self._dns_thread.start()
        time.sleep(0.05)

    def stop(self) -> None:
        self.http_server.shutdown()
        self.doh_server.shutdown()


def sha256_short(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def run_crypto_asymmetry_proof(env: LocalTestEnvironment) -> ProofResult:
    """Prove Noise_NK (`es + ee`) asymmetry, MitM resistance, and PFS."""
    q0 = env.handler.query_counter
    t0 = time.perf_counter()

    # 1. Legitimate handshake
    c1 = CryptoState(env.server_pub, is_client=True)
    s1 = CryptoState(env.server_priv, is_client=False)
    syn1 = c1.client_hello()
    synack1 = s1.server_hello(syn1)
    c1.client_finish(synack1)

    # 2. Second handshake -> verify PFS (distinct session keys)
    c2 = CryptoState(env.server_pub, is_client=True)
    s2 = CryptoState(env.server_priv, is_client=False)
    syn2 = c2.client_hello()
    synack2 = s2.server_hello(syn2)
    c2.client_finish(synack2)
    assert c1.keys.client_to_server != c2.keys.client_to_server, "PFS violated"

    # 3. Captured client key (`server_pub`) cannot impersonate relay
    impersonator = CryptoState(env.server_pub, is_client=False)
    victim = CryptoState(env.server_pub, is_client=True)
    victim_syn = victim.client_hello()
    mitm_blocked = False
    try:
        impersonator.server_hello(victim_syn)
    except ValueError:
        mitm_blocked = True
    assert mitm_blocked, "Impersonator with SERVER_PUB should not decrypt SYN!"

    pt = os.urandom(1024)
    ct = c1.encrypt(pt, aad=b"hdr01")
    dec = s1.decrypt(ct, aad=b"hdr01")
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    kbps = (len(pt) * 8 / 1000.0) / max(elapsed_ms / 1000.0, 1e-6)

    return ProofResult(
        name="Noise_NK Asymmetry + PFS + MitM Block",
        client="kopacz.protocol.crypto",
        mode="crypto-proof",
        bytes_in=len(pt),
        bytes_out=len(dec),
        sha256_in=sha256_short(pt),
        sha256_out=sha256_short(dec),
        queries=env.handler.query_counter - q0,
        elapsed_ms=elapsed_ms,
        kbps=kbps,
        passed=(pt == dec and mitm_blocked),
        note="SYN=56B, SYN-ACK=48B, SERVER_PUB cannot MitM",
    )


def run_subprocess_echo_proof(
    env: LocalTestEnvironment,
    name: str,
    client_label: str,
    cmd: list[str],
    payload: bytes,
) -> ProofResult:
    q0 = env.handler.query_counter
    t0 = time.perf_counter()
    proc = subprocess.run(
        cmd,
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    queries = env.handler.query_counter - q0
    out = proc.stdout
    kbps = (len(out) * 8 / 1000.0) / max(elapsed_ms / 1000.0, 1e-6)
    h_in = sha256_short(payload)
    h_out = sha256_short(out)
    passed = (proc.returncode == 0) and (out == payload)
    note = f"rc={proc.returncode}" if passed else f"rc={proc.returncode} err={proc.stderr.decode(errors='replace').strip()[:60]}"
    return ProofResult(
        name=name,
        client=client_label,
        mode="echo (UDP/53)",
        bytes_in=len(payload),
        bytes_out=len(out),
        sha256_in=h_in,
        sha256_out=h_out,
        queries=queries,
        elapsed_ms=elapsed_ms,
        kbps=kbps,
        passed=passed,
        note=note,
    )


def run_web_fetch_proof(env: LocalTestEnvironment, name: str, client_label: str, cmd: list[str]) -> ProofResult:
    url = f"http://127.0.0.1:{env.http_port}/article"
    expected = distill_html(env.http_payload, url)
    q0 = env.handler.query_counter
    t0 = time.perf_counter()
    proc = subprocess.run(
        cmd + [url],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=25,
        check=False,
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    queries = env.handler.query_counter - q0
    out = proc.stdout
    kbps = (len(out) * 8 / 1000.0) / max(elapsed_ms / 1000.0, 1e-6)
    passed = (
        proc.returncode == 0
        and out == expected
        and b"<script>" not in out
        and f"http://127.0.0.1:{env.http_port}/page2".encode() in out
    )
    return ProofResult(
        name=name,
        client=client_label,
        mode="fetch-reader",
        bytes_in=len(expected),
        bytes_out=len(out),
        sha256_in=sha256_short(expected),
        sha256_out=sha256_short(out),
        queries=queries,
        elapsed_ms=elapsed_ms,
        kbps=kbps,
        passed=passed,
        note="Distilled HTML (<script> stripped, LZ4 decompressed)",
    )


def run_doh_pipeline_proof(env: LocalTestEnvironment, payload: bytes) -> ProofResult:
    """Prove the RFC 8484 JSON DoH endpoint + TunnelClient pipeline used by kopacz.js/web.html."""
    import urllib.request

    class LocalDoHClientResolver:
        def __init__(self, doh_port: int):
            self.doh_port = doh_port

        def query(self, qname: str) -> Optional[str]:
            url = f"http://127.0.0.1:{self.doh_port}/dns-query?name={urllib.parse.quote(qname)}&type=TXT"
            req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                for ans in data.get("Answer", []):
                    if ans.get("type") == 16:
                        return ans.get("data", "").strip('"')
            return None

    q0 = env.handler.query_counter
    t0 = time.perf_counter()
    resolver = LocalDoHClientResolver(env.doh_port)
    client = TunnelClient(env.domain, env.server_pub, resolver, tag="dohproof", posture="turbo")
    client.connect()
    received = bytearray()
    for off in range(0, len(payload), 4096):
        chunk = payload[off : off + 4096]
        down = list(client.send(chunk))
        for d in down:
            received.extend(d)
        while len(received) < off + len(chunk):
            for p in client.poll_all(max_polls=32, retry_delay=0.01):
                received.extend(p)
    client.close()
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    queries = env.handler.query_counter - q0
    out = bytes(received)
    kbps = (len(out) * 8 / 1000.0) / max(elapsed_ms / 1000.0, 1e-6)
    return ProofResult(
        name="DoH RFC 8484 JSON Tunnel (Turbo Posture)",
        client="DoH / kopacz.js stack",
        mode="echo (DoH/HTTP)",
        bytes_in=len(payload),
        bytes_out=len(out),
        sha256_in=sha256_short(payload),
        sha256_out=sha256_short(out),
        queries=queries,
        elapsed_ms=elapsed_ms,
        kbps=kbps,
        passed=(out == payload),
        note=f"DoH endpoint 127.0.0.1:{env.doh_port}/dns-query",
    )


def run_e2e_chat_proof(env: LocalTestEnvironment) -> ProofResult:
    """Prove E2E X25519 dead-drop messaging between Alice and Bob over UDP DNS."""
    q0 = env.handler.query_counter
    t0 = time.perf_counter()

    r_alice = UDPResolver("127.0.0.1", port=env.dns_port, timeout=3.0)
    r_bob = UDPResolver("127.0.0.1", port=env.dns_port, timeout=3.0)
    t_alice = TunnelClient(env.domain, env.server_pub, r_alice, tag="appalice", posture="turbo")
    t_bob = TunnelClient(env.domain, env.server_pub, r_bob, tag="appbob01", posture="turbo")
    t_alice.connect()
    t_bob.connect()

    alice_crypto = E2ECrypto()
    bob_crypto = E2ECrypto()
    alice = MessageClient(t_alice, "alice", alice_crypto)
    bob = MessageClient(t_bob, "bob", bob_crypto)
    alice.register()
    bob.register()

    secret_msg = b"Double-layer X25519 E2E dead-drop verification payload: " + os.urandom(256)
    alice.send_message("bob", secret_msg, bob_crypto.public_key_bytes)
    inbox = bob.receive_messages()
    t_alice.close()
    t_bob.close()

    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    queries = env.handler.query_counter - q0
    got_sender, got_msg = inbox[0] if inbox else ("", b"")
    kbps = (len(got_msg) * 8 / 1000.0) / max(elapsed_ms / 1000.0, 1e-6)
    return ProofResult(
        name="E2E Dead-Drop Messaging (Alice -> Bob)",
        client="MessageClient (0x03)",
        mode="chat-e2e",
        bytes_in=len(secret_msg),
        bytes_out=len(got_msg),
        sha256_in=sha256_short(secret_msg),
        sha256_out=sha256_short(got_msg),
        queries=queries,
        elapsed_ms=elapsed_ms,
        kbps=kbps,
        passed=(got_sender == "alice" and got_msg == secret_msg),
        note=f"sender={got_sender}",
    )


def print_report(env: LocalTestEnvironment, results: list[ProofResult]) -> None:
    print("\n" + "═" * 112)
    print(" KOPACZ v3 — LIVE EXECUTION & THROUGHPUT PROOF HARNESS")
    print("═" * 112)
    print(f" Relay Domain        : {env.domain}")
    print(f" Local DNS Endpoint  : 127.0.0.1:{env.dns_port} (UDP)  |  Local DoH: http://127.0.0.1:{env.doh_port}/dns-query")
    print(f" Relay Private Key   : {env.server_priv.hex()} (stays on server)")
    print(f" Client Public Key   : {env.server_pub.hex()} (distributed to clients)")
    print("─" * 112)
    header = (
        f" {'STATUS':<6} | {'TEST / CLIENT':<38} | {'IN -> OUT (B)':<15} | "
        f"{'SHA-256 (IN == OUT)':<19} | {'QRY':>4} | {'TIME':>8} | {'SPEED':>10}"
    )
    print(header)
    print("─" * 112)
    for r in results:
        status = "PASS" if r.passed else "FAIL"
        sizes = f"{r.bytes_in} -> {r.bytes_out}"
        sha_match = f"{r.sha256_in[:8]}=={r.sha256_out[:8]}" if r.sha256_in == r.sha256_out else f"{r.sha256_in[:8]}!={r.sha256_out[:8]}"
        print(
            f" [{status}] | {r.name[:38]:<38} | {sizes:<15} | "
            f"{sha_match:<19} | {r.queries:>4} | {r.elapsed_ms:>6.1f}ms | {r.kbps:>7.1f} kbps"
        )
    print("═" * 112)
    all_ok = all(r.passed for r in results)
    print(f" Overall Verdict: {'ALL PROOFS PASSED' if all_ok else 'FAILURE DETECTED'} ({sum(r.passed for r in results)}/{len(results)})\n")


def interactive_loop(env: LocalTestEnvironment, c_bin: Path, py_cli: Path) -> None:
    print("\nEntering Interactive Harness Mode (type 'q' to quit):")
    while True:
        print("\n  [1] Send custom text message through C99 client (`clients/c/kopacz`)")
        print("  [2] Send custom random binary payload (choose byte size) through Python & C99 clients")
        print("  [3] Fetch local HTML page in Reader Mode through C99 client and inspect output")
        print("  [q] Quit")
        choice = input("\nSelect action > ").strip().lower()
        if choice in ("q", "quit", "exit"):
            break
        if choice == "1":
            msg = input("Enter text to send over DNS > ").encode("utf-8")
            res = run_subprocess_echo_proof(
                env,
                "Interactive C99 Echo",
                "clients/c/kopacz",
                [str(c_bin), "-d", env.domain, "-k", env.server_pub.hex(), "-r", f"127.0.0.1:{env.dns_port}", "echo"],
                msg,
            )
            print_report(env, [res])
        elif choice == "2":
            sz_str = input("Payload size in bytes [default 16384] > ").strip() or "16384"
            blob = os.urandom(int(sz_str))
            r_py = run_subprocess_echo_proof(
                env,
                f"Python Echo ({len(blob)} B)",
                "clients/python/kopacz_client.py",
                [sys.executable, str(py_cli), "-d", env.domain, "-k", env.server_pub.hex(), "-r", f"127.0.0.1:{env.dns_port}", "-p", "turbo", "echo"],
                blob,
            )
            r_c = run_subprocess_echo_proof(
                env,
                f"C99 Native Echo ({len(blob)} B)",
                "clients/c/kopacz",
                [str(c_bin), "-d", env.domain, "-k", env.server_pub.hex(), "-r", f"127.0.0.1:{env.dns_port}", "echo"],
                blob,
            )
            print_report(env, [r_py, r_c])
        elif choice == "3":
            res = run_c_web_fetch_proof(env, c_bin)
            print_report(env, [res])


def main() -> int:
    parser = argparse.ArgumentParser(description="Kopacz v3 Interactive Verification & Benchmark Harness")
    parser.add_argument("--size", type=int, default=16384, help="Payload size in bytes for echo throughput tests (default: 16384)")
    parser.add_argument("--interactive", "-i", action="store_true", help="Enter interactive menu after running baseline proofs")
    args = parser.parse_args()

    # Ensure C client is compiled
    c_src = REPO_ROOT / "clients" / "c" / "kopacz.c"
    c_bin = REPO_ROOT / "clients" / "c" / "kopacz"
    subprocess.run(
        ["cc", "-O2", "-Wall", "-Wextra", "-Werror", "-std=c99", str(c_src), "-o", str(c_bin)],
        check=True,
    )

    py_cli = REPO_ROOT / "clients" / "python" / "kopacz_client.py"
    bash_cli = REPO_ROOT / "clients" / "bash" / "kopacz.sh"
    ps1_cli = REPO_ROOT / "clients" / "powershell" / "kopacz.ps1"
    pwsh_bin = shutil.which("pwsh") or shutil.which("powershell")

    env = LocalTestEnvironment()
    env.start()
    try:
        payload = os.urandom(args.size)
        results: list[ProofResult] = []

        # 1. Crypto Asymmetry, MitM & PFS proof
        results.append(run_crypto_asymmetry_proof(env))

        # 2. Python Client Echo proof
        results.append(
            run_subprocess_echo_proof(
                env,
                f"Python CLI Echo ({args.size} B)",
                "clients/python/kopacz_client.py",
                [
                    sys.executable,
                    str(py_cli),
                    "-d", env.domain,
                    "-k", env.server_pub.hex(),
                    "-r", f"127.0.0.1:{env.dns_port}",
                    "-p", "turbo",
                    "echo",
                ],
                payload,
            )
        )

        # 3. C99 Native Client Echo proof
        results.append(
            run_subprocess_echo_proof(
                env,
                f"C99 Native Client Echo ({args.size} B)",
                "clients/c/kopacz",
                [
                    str(c_bin),
                    "-d", env.domain,
                    "-k", env.server_pub.hex(),
                    "-r", f"127.0.0.1:{env.dns_port}",
                    "echo",
                ],
                payload,
            )
        )

        # 4. Standalone CLI Bash Client Echo proof
        bash_size = min(2048, args.size)
        results.append(
            run_subprocess_echo_proof(
                env,
                f"Bash Pure-CLI Echo ({bash_size} B)",
                "clients/bash/kopacz.sh",
                [
                    "bash",
                    str(bash_cli),
                    "-d", env.domain,
                    "-k", env.server_pub.hex(),
                    "-r", f"127.0.0.1:{env.dns_port}",
                    "echo",
                ],
                payload[:bash_size],
            )
        )

        # 5. C99 Reader Mode Web Fetch proof
        results.append(
            run_web_fetch_proof(
                env,
                "C99 Reader Mode Web Fetch (0x04)",
                "clients/c/kopacz",
                [
                    str(c_bin),
                    "-d", env.domain,
                    "-k", env.server_pub.hex(),
                    "-r", f"127.0.0.1:{env.dns_port}",
                    "-t", "appcweb1",
                    "fetch",
                ],
            )
        )

        # 6. Standalone CLI Bash Reader Mode Web Fetch + AWK LZ4 proof
        results.append(
            run_web_fetch_proof(
                env,
                "Bash Pure-CLI Web Fetch + AWK LZ4",
                "clients/bash/kopacz.sh",
                [
                    "bash",
                    str(bash_cli),
                    "-d", env.domain,
                    "-k", env.server_pub.hex(),
                    "-r", f"127.0.0.1:{env.dns_port}",
                    "-t", "appbweb1",
                    "fetch",
                ],
            )
        )

        # Optional: Standalone .NET / PowerShell Client proof (when pwsh is installed)
        if pwsh_bin:
            results.append(
                run_subprocess_echo_proof(
                    env,
                    f"PowerShell .NET Core Echo ({bash_size} B)",
                    "clients/powershell/kopacz.ps1",
                    [
                        pwsh_bin,
                        "-NoProfile",
                        "-File",
                        str(ps1_cli),
                        "-d", env.domain,
                        "-k", env.server_pub.hex(),
                        "-r", f"127.0.0.1:{env.dns_port}",
                        "echo",
                    ],
                    payload[:bash_size],
                )
            )

        # 6. DoH RFC 8484 JSON Pipeline proof
        results.append(run_doh_pipeline_proof(env, payload))

        # 7. E2E Dead-Drop Messaging proof
        results.append(run_e2e_chat_proof(env))

        print_report(env, results)

        if args.interactive:
            interactive_loop(env, c_bin, py_cli)

        return 0 if all(r.passed for r in results) else 1
    finally:
        env.stop()


if __name__ == "__main__":
    raise SystemExit(main())
