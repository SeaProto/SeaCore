#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import socket
import subprocess
import tempfile
import threading
import time
import contextlib
from collections import Counter
from pathlib import Path

import psutil


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "target" / "release" / ("seacore.exe" if os.name == "nt" else "seacore")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_port(port: int, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            try:
                sock.connect(("127.0.0.1", port))
                return True
            except OSError:
                time.sleep(0.1)
    return False


def kill_stale_seacore() -> None:
    for proc in psutil.process_iter(attrs=["name"]):
        try:
            name = (proc.info.get("name") or "").lower()
            if name.startswith("seacore"):
                proc.kill()
        except Exception:
            pass


def cpu_sample(proc: psutil.Process, seconds: float, step: float = 0.5) -> dict[str, float | int]:
    logical = max(psutil.cpu_count(logical=True) or 1, 1)
    proc.cpu_percent(None)

    values_raw: list[float] = []
    end = time.time() + seconds
    while time.time() < end:
        values_raw.append(proc.cpu_percent(interval=step))

    values_norm = [v / logical for v in values_raw]
    return {
        "avg_raw": sum(values_raw) / len(values_raw) if values_raw else 0.0,
        "peak_raw": max(values_raw) if values_raw else 0.0,
        "avg_norm": sum(values_norm) / len(values_norm) if values_norm else 0.0,
        "peak_norm": max(values_norm) if values_norm else 0.0,
        "samples": len(values_raw),
    }


def tcp_summary(proc: psutil.Process, socks_port: int, server_port: int) -> dict[str, object]:
    try:
        conns = proc.net_connections(kind="tcp")
    except Exception:
        return {"error": "no-access"}

    states = Counter(c.status for c in conns)
    return {
        "total": len(conns),
        "states": dict(states),
        "remote_443": sum(1 for c in conns if c.raddr and c.raddr.port == 443),
        "local_socks": sum(1 for c in conns if c.laddr and c.laddr.port == socks_port),
        "local_server": sum(1 for c in conns if c.laddr and c.laddr.port == server_port),
    }


def build_config_files(
    temp_dir: Path,
    server_port: int,
    socks_port: int,
    transport: str,
) -> tuple[Path, Path]:
    server_cfg = {
        "listen": f"127.0.0.1:{server_port}",
        "users": [
            {
                "uuid": "762d4f3d-6b10-4539-9c8e-933487d4ec2a",
                "password": "57253b85-3e75-4eea-aa57-342a6bc993bf",
            }
        ],
        "handshake_timeout_secs": 5,
        "connection_idle_timeout_secs": 10,
        "half_close_timeout_secs": 2,
        "idle_session_check_interval_secs": 5,
        "idle_session_timeout_secs": 10,
        "min_idle_sessions": 0,
        "metrics_listen": f"127.0.0.1:{free_port()}",
        "reality": {
            "dest": "www.apple.com:443",
            "server_names": ["www.apple.com"],
            "private_key": "mVxOWKC+adctWqUNc69aq3ROyKI5dOuSr2mOPN7QjXU=",
            "short_ids": ["77962d1eb98d1274"],
        },
    }

    client_cfg = {
        "server": f"127.0.0.1:{server_port}",
        "server_name": "www.apple.com",
        "uuid": "762d4f3d-6b10-4539-9c8e-933487d4ec2a",
        "password": "57253b85-3e75-4eea-aa57-342a6bc993bf",
        "socks5_listen": f"127.0.0.1:{socks_port}",
        "transport": transport,
        "insecure_skip_verify": False,
        "handshake_timeout_secs": 5,
        "connection_idle_timeout_secs": 10,
        "half_close_timeout_secs": 2,
        "idle_session_check_interval_secs": 5,
        "idle_session_timeout_secs": 10,
        "min_idle_sessions": 0,
        "metrics_listen": f"127.0.0.1:{free_port()}",
        "reality": {
            "server_name": "www.apple.com",
            "public_key": "aZvTNUF7k+E4NA8rERfplYkoq/AcJ5y9UCiTU+nPH3U=",
            "short_id": "77962d1eb98d1274",
            "profile": "chrome",
            "spider_x": "/",
        },
    }

    server_json = temp_dir / "server.profile.json"
    client_json = temp_dir / "client.profile.json"
    server_json.write_text(json.dumps(server_cfg, indent=2), encoding="utf-8")
    client_json.write_text(json.dumps(client_cfg, indent=2), encoding="utf-8")
    return server_json, client_json


def tail(path: Path, lines: int = 40) -> list[str]:
    if not path.exists():
        return ["<missing log>"]
    data = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return data[-lines:]


def main() -> int:
    if not BIN.exists():
        print(f"binary not found: {BIN}")
        print("build first: cargo build --release -p seacore")
        return 2

    transport = os.environ.get("SEACORE_PROFILE_TRANSPORT", "tcp").strip().lower() or "tcp"

    kill_stale_seacore()
    server_port = free_port()
    socks_port = free_port()

    with tempfile.TemporaryDirectory(prefix="seacore-prof-") as td:
        temp_dir = Path(td)
        server_json, client_json = build_config_files(
            temp_dir,
            server_port,
            socks_port,
            transport,
        )
        server_log = temp_dir / "server.log"
        client_log = temp_dir / "client.log"

        server_proc = subprocess.Popen(
            [str(BIN), "server", "--config", str(server_json)],
            cwd=str(ROOT),
            stdout=server_log.open("w", encoding="utf-8"),
            stderr=subprocess.STDOUT,
        )
        client_proc = subprocess.Popen(
            [str(BIN), "client", "--config", str(client_json)],
            cwd=str(ROOT),
            stdout=client_log.open("w", encoding="utf-8"),
            stderr=subprocess.STDOUT,
        )

        try:
            if not wait_port(server_port, timeout=20):
                raise RuntimeError("server port did not open")
            if not wait_port(socks_port, timeout=30):
                raise RuntimeError("SOCKS port did not open")

            p_server = psutil.Process(server_proc.pid)
            p_client = psutil.Process(client_proc.pid)
            print(f"PIDs: server={server_proc.pid}, client={client_proc.pid}")
            print(f"Ports: server={server_port}, socks={socks_port}, transport={transport}")

            idle_server = cpu_sample(p_server, seconds=8)
            idle_client = cpu_sample(p_client, seconds=8)

            load_stats = {"ok": 0, "fail": 0}
            stop = threading.Event()

            def load_loop() -> None:
                while not stop.is_set():
                    cmd = [
                        "curl.exe",
                        "--silent",
                        "--show-error",
                        "--head",
                        "--output",
                        "NUL",
                        "--socks5-hostname",
                        f"127.0.0.1:{socks_port}",
                        "https://www.google.com",
                    ]

                    batch: list[subprocess.Popen[bytes]] = []
                    for _ in range(12):
                        batch.append(
                            subprocess.Popen(
                                cmd,
                                cwd=str(ROOT),
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                            )
                        )

                    for proc in batch:
                        try:
                            rc = proc.wait(timeout=20)
                            if rc == 0:
                                load_stats["ok"] += 1
                            else:
                                load_stats["fail"] += 1
                        except Exception:
                            load_stats["fail"] += 1
                            with contextlib.suppress(Exception):
                                proc.kill()

            load_thread = threading.Thread(target=load_loop, daemon=True)
            load_thread.start()

            load_server = cpu_sample(p_server, seconds=18)
            load_client = cpu_sample(p_client, seconds=18)

            stop.set()
            load_thread.join(timeout=5)

            post_server = cpu_sample(p_server, seconds=6)
            post_client = cpu_sample(p_client, seconds=6)

            tcp_server = tcp_summary(p_server, socks_port=socks_port, server_port=server_port)
            tcp_client = tcp_summary(p_client, socks_port=socks_port, server_port=server_port)

            print("=== CPU BASELINE (idle) ===")
            print(json.dumps({"server": idle_server, "client": idle_client}, indent=2))
            print("=== CPU UNDER LOAD (parallel curl google) ===")
            print(
                json.dumps(
                    {
                        "server": load_server,
                        "client": load_client,
                        "requests": load_stats,
                    },
                    indent=2,
                )
            )
            print("=== CPU AFTER LOAD ===")
            print(json.dumps({"server": post_server, "client": post_client}, indent=2))
            print("=== TCP SNAPSHOT ===")
            print(json.dumps({"server": tcp_server, "client": tcp_client}, indent=2))

            print("=== SERVER LOG TAIL ===")
            for line in tail(server_log, 50):
                print(line)
            print("=== CLIENT LOG TAIL ===")
            for line in tail(client_log, 50):
                print(line)

        finally:
            for proc in (client_proc, server_proc):
                try:
                    proc.terminate()
                except Exception:
                    pass
            time.sleep(0.5)
            for proc in (client_proc, server_proc):
                if proc.poll() is None:
                    try:
                        proc.kill()
                    except Exception:
                        pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
    transport = os.environ.get("SEACORE_PROFILE_TRANSPORT", "tcp").strip().lower() or "tcp"
