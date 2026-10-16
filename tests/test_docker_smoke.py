import socket
import subprocess
import time
from pathlib import Path

import pytest

from proxycli.constants import THREEPROXY_IMAGE
from proxycli.models.config import AppConfig, Listener, ProxyUser
from proxycli.services.probes import http_proxy_status, socks5_connect, socks5_noauth_rejected
from proxycli.services.proxy3cfg import render_3proxy


def _docker_ok() -> bool:
    try:
        result = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


@pytest.mark.skipif(not _docker_ok(), reason="Docker недоступен: smoke SOCKS5/HTTP CONNECT пропущен")
def test_docker_proxy_auth_and_ssrf(tmp_path: Path):
    config = AppConfig(
        socks=Listener(enabled=True, port=1080, users=[ProxyUser("alice", "socks:alice")]),
        http=Listener(enabled=True, port=3128, users=[ProxyUser("alice", "http:alice")]),
    )
    secrets = {"socks:alice": "AlicePassword1", "http:alice": "AlicePassword1"}
    cfg = tmp_path / "3proxy.cfg"
    cfg.write_text(render_3proxy(config, secrets), encoding="utf-8")
    name = "proxycli-smoke-test"
    subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True)
    pull = subprocess.run(["docker", "pull", THREEPROXY_IMAGE], capture_output=True, text=True, timeout=180)
    if pull.returncode != 0:
        pytest.skip(f"образ {THREEPROXY_IMAGE} не скачан: {pull.stderr.strip()}")
    run = subprocess.run(
        [
            "docker", "run", "-d", "--name", name, "--read-only",
            "-p", "127.0.0.1:0:1080", "-p", "127.0.0.1:0:3128",
            "-v", f"{cfg.resolve().as_posix()}:/etc/3proxy/3proxy.cfg:ro",
            THREEPROXY_IMAGE,
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    try:
        assert run.returncode == 0, run.stderr
        socks_port = _published(name, "1080/tcp")
        http_port = _published(name, "3128/tcp")
        _wait(socks_port)
        assert socks5_noauth_rejected("127.0.0.1", socks_port, 5) is True
        anonymous = http_proxy_status("127.0.0.1", http_port, "1.1.1.1", 443, 5)
        assert anonymous == 407
        try:
            blocked = socks5_connect("127.0.0.1", socks_port, "alice", "AlicePassword1", "127.0.0.1", 9, 5)
        except Exception:
            blocked = 1
        assert blocked != 0
        metadata = http_proxy_status(
            "127.0.0.1", http_port, "169.254.169.254", 80, 5, username="alice", password="AlicePassword1"
        )
        assert metadata != 200
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True)


def _published(name: str, container_port: str) -> int:
    result = subprocess.run(["docker", "port", name, container_port], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    return int(result.stdout.strip().rsplit(":", 1)[-1])


def _wait(port: int) -> None:
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.3)
    raise AssertionError(f"порт {port} не открылся")
