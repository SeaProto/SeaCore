#!/usr/bin/env python3
"""
Deterministic SeaCore local test matrix.

Coverage:
- long-run stress (TCP + UDP)
- reconnect after server outage
- SOCKS5 UDP NAT rebinding behavior
- cross-platform end-to-end checks (Windows/Linux/macOS)

The script only uses loopback services to avoid external network flakiness.
"""

from __future__ import annotations

import argparse
import collections
import contextlib
import http.client
import http.server
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Deque, Iterable, Optional, Tuple


SHORT_ID = "77962d1eb98d1274"
REALITY_PRIVATE_KEY = "mVxOWKC+adctWqUNc69aq3ROyKI5dOuSr2mOPN7QjXU="
REALITY_PUBLIC_KEY = "aZvTNUF7k+E4NA8rERfplYkoq/AcJ5y9UCiTU+nPH3U="


class TestFailure(RuntimeError):
    pass


def info(msg: str) -> None:
    print(f"[INFO] {msg}", flush=True)


def step(msg: str) -> None:
    print(f"\n[STEP] {msg}", flush=True)


def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_tcp_port(host: str, port: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            try:
                sock.connect((host, port))
                return True
            except OSError:
                time.sleep(0.1)
    return False


class BufferedProcess:
    def __init__(self, name: str, args: Iterable[str], cwd: Path):
        self.name = name
        self.args = list(args)
        self.cwd = cwd
        self.proc: Optional[subprocess.Popen[str]] = None
        self._logs: Deque[str] = collections.deque(maxlen=300)
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self.proc is not None:
            raise RuntimeError(f"process {self.name} already started")
        self.proc = subprocess.Popen(
            self.args,
            cwd=str(self.cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        self._thread = threading.Thread(target=self._read_logs, daemon=True)
        self._thread.start()

    def _read_logs(self) -> None:
        assert self.proc is not None
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self._logs.append(line.rstrip())

    def is_running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self) -> None:
        if self.proc is None:
            return

        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)

        if self._thread is not None:
            self._thread.join(timeout=1)

    def restart(self) -> None:
        self.stop()
        self.proc = None
        self._thread = None
        self.start()

    def ensure_running(self) -> None:
        if not self.is_running():
            raise TestFailure(
                f"{self.name} exited unexpectedly with code "
                f"{None if self.proc is None else self.proc.returncode}\n"
                f"Recent logs:\n{self.recent_logs()}"
            )

    def recent_logs(self) -> str:
        if not self._logs:
            return "<no logs captured>"
        return "\n".join(self._logs)


class QuietHTTPHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        body = f"seacore-e2e-ok:{self.server.token}\n".encode("utf-8")  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        _ = format, args
        return


class ThreadedHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True


class UdpEchoServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((self.host, self.port))
        self._sock.settimeout(0.2)
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        assert self._sock is not None
        while not self._stop_event.is_set():
            try:
                data, addr = self._sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._sock.sendto(data, addr)
            except OSError:
                break

    def stop(self) -> None:
        self._stop_event.set()
        if self._sock is not None:
            with contextlib.suppress(OSError):
                self._sock.close()
        if self._thread is not None:
            self._thread.join(timeout=1)


def read_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise TestFailure(f"socket closed while waiting for {size} bytes")
        data.extend(chunk)
    return bytes(data)


def socks5_handshake(sock: socket.socket) -> None:
    sock.sendall(b"\x05\x01\x00")
    resp = read_exact(sock, 2)
    if resp != b"\x05\x00":
        raise TestFailure(f"SOCKS5 handshake failed: {resp.hex()}")


def parse_socks5_bind_addr(sock: socket.socket) -> Tuple[str, int]:
    head = read_exact(sock, 4)
    if head[1] != 0x00:
        raise TestFailure(f"SOCKS5 command failed with REP={head[1]:#x}")
    atyp = head[3]
    if atyp == 0x01:
        addr = socket.inet_ntoa(read_exact(sock, 4))
    elif atyp == 0x04:
        addr = socket.inet_ntop(socket.AF_INET6, read_exact(sock, 16))
    elif atyp == 0x03:
        length = read_exact(sock, 1)[0]
        addr = read_exact(sock, length).decode("utf-8", "replace")
    else:
        raise TestFailure(f"unexpected SOCKS5 ATYP {atyp:#x}")

    port = struct.unpack("!H", read_exact(sock, 2))[0]
    return addr, port


def socks5_connect_v4(socks_port: int, dst_port: int, timeout: float = 5.0) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", socks_port), timeout=timeout)
    sock.settimeout(timeout)
    socks5_handshake(sock)

    req = b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", dst_port)
    sock.sendall(req)
    _ = parse_socks5_bind_addr(sock)
    return sock


def socks5_udp_associate(socks_port: int, timeout: float = 5.0) -> Tuple[socket.socket, Tuple[str, int]]:
    sock = socket.create_connection(("127.0.0.1", socks_port), timeout=timeout)
    sock.settimeout(timeout)
    socks5_handshake(sock)

    req = b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00"
    sock.sendall(req)
    relay_host, relay_port = parse_socks5_bind_addr(sock)
    if relay_host == "0.0.0.0":
        relay_host = "127.0.0.1"
    return sock, (relay_host, relay_port)


def build_socks5_udp_packet(target_host: str, target_port: int, payload: bytes) -> bytes:
    return (
        b"\x00\x00\x00\x01"
        + socket.inet_aton(target_host)
        + struct.pack("!H", target_port)
        + payload
    )


def parse_socks5_udp_packet(packet: bytes) -> Tuple[str, int, bytes]:
    if len(packet) < 10:
        raise TestFailure(f"SOCKS5 UDP packet too short: {len(packet)}")
    if packet[0:2] != b"\x00\x00":
        raise TestFailure("SOCKS5 UDP RSV mismatch")
    if packet[2] != 0x00:
        raise TestFailure("SOCKS5 UDP FRAG is not zero")
    atyp = packet[3]
    if atyp == 0x01:
        host = socket.inet_ntoa(packet[4:8])
        port = struct.unpack("!H", packet[8:10])[0]
        payload = packet[10:]
        return host, port, payload
    raise TestFailure(f"unsupported SOCKS5 UDP ATYP={atyp:#x}")


def tcp_roundtrip(socks_port: int, backend_tcp_port: int, token: str) -> None:
    with socks5_connect_v4(socks_port, backend_tcp_port) as sock:
        req = (
            "GET /health HTTP/1.1\r\n"
            "Host: 127.0.0.1\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("utf-8")
        sock.sendall(req)

        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)

    raw = b"".join(chunks)
    if b"HTTP/1.1 200" not in raw and b"HTTP/1.0 200" not in raw:
        raise TestFailure(f"unexpected HTTP response status: {raw[:120]!r}")
    marker = f"seacore-e2e-ok:{token}".encode("utf-8")
    if marker not in raw:
        raise TestFailure("TCP roundtrip body marker mismatch")


def udp_roundtrip(
    relay: Tuple[str, int],
    backend_udp_port: int,
    payload: bytes,
    udp_sock: Optional[socket.socket] = None,
    timeout: float = 3.0,
) -> None:
    owns_socket = udp_sock is None
    if udp_sock is None:
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.bind(("127.0.0.1", 0))
    udp_sock.settimeout(timeout)

    packet = build_socks5_udp_packet("127.0.0.1", backend_udp_port, payload)
    udp_sock.sendto(packet, relay)
    data, _ = udp_sock.recvfrom(65535)
    src_host, src_port, echoed = parse_socks5_udp_packet(data)

    if src_host != "127.0.0.1" or src_port != backend_udp_port:
        raise TestFailure(
            f"UDP source mismatch: expected 127.0.0.1:{backend_udp_port}, "
            f"got {src_host}:{src_port}"
        )
    if echoed != payload:
        raise TestFailure("UDP payload mismatch")

    if owns_socket:
        udp_sock.close()


def fetch_metrics_text(port: int) -> str:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        conn.request("GET", "/metrics")
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", "replace")
        if resp.status != 200:
            raise TestFailure(f"metrics endpoint returned HTTP {resp.status}")
        return body
    finally:
        conn.close()


def metric_value(metrics_text: str, metric_name: str) -> float:
    for line in metrics_text.splitlines():
        if line.startswith(metric_name + " "):
            raw = line.split(" ", 1)[1].strip()
            return float(raw)
    raise TestFailure(f"metric {metric_name} not found")


def run_long_stability(
    socks_port: int,
    backend_tcp_port: int,
    backend_udp_port: int,
    token: str,
    tcp_iterations: int,
    udp_iterations: int,
) -> None:
    step(f"long-run stability: tcp={tcp_iterations}, udp={udp_iterations}")

    for i in range(tcp_iterations):
        tcp_roundtrip(socks_port, backend_tcp_port, token)
        if (i + 1) % 10 == 0:
            info(f"TCP iterations completed: {i + 1}/{tcp_iterations}")

    ctrl, relay = socks5_udp_associate(socks_port)
    try:
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.bind(("127.0.0.1", 0))
        try:
            for i in range(udp_iterations):
                payload = f"udp-long-{i}".encode("utf-8")
                udp_roundtrip(relay, backend_udp_port, payload, udp_sock=udp_sock)
                if (i + 1) % 20 == 0:
                    info(f"UDP iterations completed: {i + 1}/{udp_iterations}")
        finally:
            udp_sock.close()
    finally:
        ctrl.close()


def run_nat_rebinding(socks_port: int, backend_udp_port: int) -> None:
    step("UDP NAT rebinding simulation")
    ctrl, relay = socks5_udp_associate(socks_port)
    try:
        sock_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_a.bind(("127.0.0.1", 0))
        sock_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            port_a = sock_a.getsockname()[1]
            udp_roundtrip(relay, backend_udp_port, b"nat-rebind-a", udp_sock=sock_a)

            sock_b.bind(("127.0.0.1", 0))
            port_b = sock_b.getsockname()[1]
            if port_a == port_b:
                raise TestFailure(
                    "NAT rebinding check requires a different local UDP source port"
                )
            udp_roundtrip(relay, backend_udp_port, b"nat-rebind-b", udp_sock=sock_b)

            info(
                f"UDP source port changed {port_a} -> {port_b} and association stayed valid"
            )
        finally:
            sock_b.close()
            sock_a.close()
    finally:
        ctrl.close()


def run_reconnect_test(
    server_proc: BufferedProcess,
    client_proc: BufferedProcess,
    server_port: int,
    socks_port: int,
    backend_tcp_port: int,
    token: str,
    client_metrics_port: int,
) -> None:
    step("reconnect after server outage")

    baseline_metrics = fetch_metrics_text(client_metrics_port)
    reconnect_before = metric_value(baseline_metrics, "seacore_client_reconnects_total")

    server_proc.stop()
    info("server stopped")
    time.sleep(3)
    server_proc.restart()

    if not wait_for_tcp_port("127.0.0.1", server_port, timeout=12):
        raise TestFailure("server did not reopen listen port after restart")

    deadline = time.monotonic() + 35
    last_error: Optional[str] = None
    while time.monotonic() < deadline:
        server_proc.ensure_running()
        client_proc.ensure_running()
        try:
            tcp_roundtrip(socks_port, backend_tcp_port, token)
            break
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
            time.sleep(1)
    else:
        raise TestFailure(f"proxy did not recover after restart: {last_error}")

    metric_deadline = time.monotonic() + 20
    while time.monotonic() < metric_deadline:
        metrics = fetch_metrics_text(client_metrics_port)
        reconnect_after = metric_value(metrics, "seacore_client_reconnects_total")
        if reconnect_after > reconnect_before:
            info(
                "reconnect metric advanced "
                f"{reconnect_before:.0f} -> {reconnect_after:.0f}"
            )
            return
        time.sleep(1)

    raise TestFailure("client reconnect metric did not increase after server restart")


def detect_binary(repo_root: Path, provided: Optional[str]) -> Path:
    if provided:
        p = Path(provided)
        if p.is_absolute():
            return p
        return (repo_root / p).resolve()

    exe = "seacore.exe" if os.name == "nt" else "seacore"
    return (repo_root / "target" / "release" / exe).resolve()


def write_config_files(
    temp_dir: Path,
    server_port: int,
    socks_port: int,
    fallback_port: int,
    server_metrics_port: int,
    client_metrics_port: int,
    user_uuid: str,
    password: str,
) -> Tuple[Path, Path]:
    server_cfg = {
        "listen": f"127.0.0.1:{server_port}",
        "users": [{"uuid": user_uuid, "password": password}],
        "handshake_timeout_secs": 5,
        "connection_idle_timeout_secs": 10,
        "half_close_timeout_secs": 2,
        "idle_session_check_interval_secs": 2,
        "idle_session_timeout_secs": 8,
        "min_idle_sessions": 0,
        "metrics_listen": f"127.0.0.1:{server_metrics_port}",
        "reality": {
            "dest": f"127.0.0.1:{fallback_port}",
            "server_names": ["localhost"],
            "private_key": REALITY_PRIVATE_KEY,
            "short_ids": [SHORT_ID],
        },
    }

    client_cfg = {
        "server": f"127.0.0.1:{server_port}",
        "uuid": user_uuid,
        "password": password,
        "socks5_listen": f"127.0.0.1:{socks_port}",
        "transport": "auto",
        "insecure_skip_verify": False,
        "handshake_timeout_secs": 5,
        "connection_idle_timeout_secs": 10,
        "half_close_timeout_secs": 2,
        "idle_session_check_interval_secs": 2,
        "idle_session_timeout_secs": 8,
        "min_idle_sessions": 0,
        "metrics_listen": f"127.0.0.1:{client_metrics_port}",
        "reality": {
            "server_name": "localhost",
            "profile": "chrome",
            "public_key": REALITY_PUBLIC_KEY,
            "short_id": SHORT_ID,
        },
    }

    server_path = temp_dir / "server.matrix.json"
    client_path = temp_dir / "client.matrix.json"
    server_path.write_text(json.dumps(server_cfg, indent=2), encoding="utf-8")
    client_path.write_text(json.dumps(client_cfg, indent=2), encoding="utf-8")
    return server_path, client_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SeaCore deterministic local test matrix")
    parser.add_argument("--binary", help="Path to seacore executable (default: target/release)")
    parser.add_argument("--tcp-iterations", type=int, default=40)
    parser.add_argument("--udp-iterations", type=int, default=80)
    parser.add_argument("--skip-long", action="store_true")
    parser.add_argument("--skip-nat", action="store_true")
    parser.add_argument("--skip-reconnect", action="store_true")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    binary = detect_binary(repo_root, args.binary)
    if not binary.exists():
        print(
            f"[ERROR] seacore binary not found: {binary}\n"
            "Build first: cargo build --release -p seacore",
            file=sys.stderr,
        )
        return 2

    info(f"using binary: {binary}")

    backend_tcp_port = free_tcp_port()
    backend_udp_port = free_tcp_port()
    server_port = free_tcp_port()
    socks_port = free_tcp_port()
    server_metrics_port = free_tcp_port()
    client_metrics_port = free_tcp_port()
    token = str(uuid.uuid4())

    http_server = ThreadedHTTPServer(("127.0.0.1", backend_tcp_port), QuietHTTPHandler)
    setattr(http_server, "token", token)
    http_thread = threading.Thread(target=http_server.serve_forever, daemon=True)

    udp_server = UdpEchoServer("127.0.0.1", backend_udp_port)

    with tempfile.TemporaryDirectory(prefix="seacore-matrix-") as tmp:
        temp_dir = Path(tmp)
        user_uuid = str(uuid.uuid4())
        password = str(uuid.uuid4())
        server_cfg, client_cfg = write_config_files(
            temp_dir=temp_dir,
            server_port=server_port,
            socks_port=socks_port,
            fallback_port=backend_tcp_port,
            server_metrics_port=server_metrics_port,
            client_metrics_port=client_metrics_port,
            user_uuid=user_uuid,
            password=password,
        )

        server_proc = BufferedProcess(
            "seacore-server",
            [str(binary), "server", "--config", str(server_cfg)],
            cwd=repo_root,
        )
        client_proc = BufferedProcess(
            "seacore-client",
            [str(binary), "client", "--config", str(client_cfg)],
            cwd=repo_root,
        )

        try:
            step("start local backends")
            http_thread.start()
            udp_server.start()

            step("start seacore server and client")
            server_proc.start()
            if not wait_for_tcp_port("127.0.0.1", server_port, timeout=12):
                raise TestFailure("server listen port did not open")

            client_proc.start()
            if not wait_for_tcp_port("127.0.0.1", socks_port, timeout=20):
                raise TestFailure("client SOCKS5 listen port did not open")

            server_proc.ensure_running()
            client_proc.ensure_running()

            step("sanity: tcp and udp roundtrip")
            tcp_roundtrip(socks_port, backend_tcp_port, token)
            ctrl, relay = socks5_udp_associate(socks_port)
            try:
                udp_roundtrip(relay, backend_udp_port, b"sanity-udp")
            finally:
                ctrl.close()

            if not args.skip_long:
                run_long_stability(
                    socks_port=socks_port,
                    backend_tcp_port=backend_tcp_port,
                    backend_udp_port=backend_udp_port,
                    token=token,
                    tcp_iterations=max(args.tcp_iterations, 1),
                    udp_iterations=max(args.udp_iterations, 1),
                )

            if not args.skip_nat:
                run_nat_rebinding(socks_port, backend_udp_port)

            if not args.skip_reconnect:
                run_reconnect_test(
                    server_proc=server_proc,
                    client_proc=client_proc,
                    server_port=server_port,
                    socks_port=socks_port,
                    backend_tcp_port=backend_tcp_port,
                    token=token,
                    client_metrics_port=client_metrics_port,
                )

            step("done")
            print("[PASS] SeaCore local matrix passed", flush=True)
            return 0
        except Exception as exc:  # noqa: BLE001
            print(f"\n[FAIL] {exc}", file=sys.stderr, flush=True)
            print("\n--- server logs (tail) ---", file=sys.stderr)
            print(server_proc.recent_logs(), file=sys.stderr)
            print("\n--- client logs (tail) ---", file=sys.stderr)
            print(client_proc.recent_logs(), file=sys.stderr)
            return 1
        finally:
            client_proc.stop()
            server_proc.stop()
            udp_server.stop()
            http_server.shutdown()
            http_server.server_close()


if __name__ == "__main__":
    sys.exit(main())
