import socket
import subprocess
import time
from pathlib import Path

import pytest

from proxycli.constants import CADDY_IMAGE, THREEPROXY_IMAGE
from proxycli.models.config import AppConfig, Listener, ProxyUser, Route
from proxycli.services.caddyfile import render_caddyfile
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


@pytest.mark.skipif(not _docker_ok(), reason="Docker недоступен: проверка caddy reload пропущена")
def test_caddy_reload_address_is_ipv4_admin(tmp_path: Path):
    caddyfile = tmp_path / "Caddyfile"
    caddyfile.write_text("{\n\tadmin 127.0.0.1:2019\n}\n:80 {\n\trespond \"ok\" 200\n}\n", encoding="utf-8")
    name = "proxycli-caddy-admin-proof"
    subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True)
    pull = subprocess.run(["docker", "pull", CADDY_IMAGE], capture_output=True, text=True, timeout=180)
    if pull.returncode != 0:
        pytest.skip(f"образ {CADDY_IMAGE} не скачан: {pull.stderr.strip()}")
    mounted = f"{caddyfile.resolve().as_posix()}:/etc/caddy/Caddyfile:ro"
    validate = subprocess.run(
        [
            "docker", "run", "--rm", "--network", "none",
            "-v", mounted,
            CADDY_IMAGE,
            "caddy", "validate",
            "--config", "/etc/caddy/Caddyfile",
            "--adapter", "caddyfile",
        ],
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert validate.returncode == 0, validate.stderr or validate.stdout
    run = subprocess.run(
        [
            "docker", "run", "-d", "--name", name, "--network", "none",
            "-v", mounted,
            CADDY_IMAGE,
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    try:
        assert run.returncode == 0, run.stderr
        ports = subprocess.run(["docker", "port", name], capture_output=True, text=True, timeout=20)
        assert ports.stdout.strip() == ""
        reloaded = _reload_until(name, ["--address", "127.0.0.1:2019"])
        assert reloaded.returncode == 0, reloaded.stderr or reloaded.stdout
        combined = f"{reloaded.stdout}\n{reloaded.stderr}"
        assert "connection refused" not in combined
        ipv6 = subprocess.run(
            _reload_argv(name, ["--address", "[::1]:2019"]),
            capture_output=True,
            text=True,
            timeout=30,
        )
        ipv6_text = f"{ipv6.stdout}\n{ipv6.stderr}"
        assert ipv6.returncode != 0
        assert "connection refused" in ipv6_text
        assert "[::1]:2019" in ipv6_text
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True)


@pytest.mark.skipif(not _docker_ok(), reason="Docker недоступен: caddy validate базового пути пропущен")
def test_caddy_validate_base_path_route(tmp_path: Path):
    config = AppConfig(
        wildcard_domain="hooks.example.com",
        routes=[
            Route(
                subdomain="tgadminbot",
                upstream="https://api.stage.dddevspace.ru/admin/admin_api/telegram/webhook/",
            )
        ],
    )
    config.tls.acme_email = "admin@example.com"
    text, _warnings = render_caddyfile(config)
    assert "rewrite * /admin/admin_api/telegram/webhook{http.request.uri}" in text
    caddyfile = tmp_path / "Caddyfile"
    caddyfile.write_text(text, encoding="utf-8", newline="\n")
    mounted = f"{caddyfile.resolve().as_posix()}:/etc/caddy/Caddyfile:ro"
    validate = subprocess.run(
        [
            "docker", "run", "--rm", "--network", "none",
            "-v", mounted,
            CADDY_IMAGE,
            "caddy", "validate",
            "--config", "/etc/caddy/Caddyfile",
            "--adapter", "caddyfile",
        ],
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert validate.returncode == 0, validate.stderr or validate.stdout


def _reload_argv(name: str, extra: list[str]) -> list[str]:
    return [
        "docker", "exec", name, "caddy", "reload",
        "--config", "/etc/caddy/Caddyfile",
        "--adapter", "caddyfile",
        *extra,
    ]


def _reload_until(name: str, extra: list[str]) -> subprocess.CompletedProcess[str]:
    deadline = time.time() + 20
    last = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="")
    while time.time() < deadline:
        last = subprocess.run(_reload_argv(name, extra), capture_output=True, text=True, timeout=30)
        if last.returncode == 0:
            return last
        time.sleep(0.4)
    return last


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
