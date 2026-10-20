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


CURL_IMAGE = "curlimages/curl:8.10.1"


@pytest.mark.skipif(not _docker_ok(), reason="Docker недоступен: проверка allowlist 3proxy пропущена")
def test_docker_socks_allowlist_by_source_ip(tmp_path: Path):
    """Real 3proxy with the generated ACL; clients get fixed source IPs on a private network.

    Code 3 means the ACL rejected the source; any other code for the allowed
    client means it passed auth and the ACL (the target may still be unreachable
    without internet).
    """
    subnet, proxy_ip, allowed_ip, denied_ip = "172.31.211.0/24", "172.31.211.2", "172.31.211.10", "172.31.211.20"
    config = AppConfig(
        socks=Listener(
            enabled=True,
            port=1080,
            allowlist=["198.51.100.20", allowed_ip],
            users=[ProxyUser("grafana", "socks:grafana"), ProxyUser("alice", "socks:alice")],
        )
    )
    secret = "GrafanaSmoke123"
    cfg = tmp_path / "3proxy.cfg"
    cfg.write_text(
        render_3proxy(config, {"socks:grafana": secret, "socks:alice": "AlicePassword1"}),
        encoding="utf-8",
        newline="\n",
    )
    for image in (THREEPROXY_IMAGE, CURL_IMAGE):
        pull = subprocess.run(["docker", "pull", image], capture_output=True, text=True, timeout=180)
        if pull.returncode != 0:
            pytest.skip(f"образ {image} не скачан: {pull.stderr.strip()}")
    network, name = "proxycli-acl-test", "proxycli-acl-test"
    subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True)
    subprocess.run(["docker", "network", "rm", network], capture_output=True, text=True)
    made = subprocess.run(
        ["docker", "network", "create", "--subnet", subnet, network], capture_output=True, text=True, timeout=30
    )
    if made.returncode != 0:
        pytest.skip(f"сеть {subnet} не создана: {made.stderr.strip()}")
    try:
        run = subprocess.run(
            [
                "docker", "run", "-d", "--name", name, "--read-only",
                "--network", network, "--ip", proxy_ip,
                "-v", f"{cfg.resolve().as_posix()}:/etc/3proxy/3proxy.cfg:ro",
                THREEPROXY_IMAGE,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert run.returncode == 0, run.stderr
        time.sleep(1)

        def client(source: str, auth: str) -> None:
            subprocess.run(
                [
                    "docker", "run", "--rm", "--network", network, "--ip", source, CURL_IMAGE,
                    "-s", "-o", "/dev/null", "--max-time", "8",
                    "--socks5", f"{auth}{proxy_ip}:1080", "http://1.1.1.1/",
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )

        client(allowed_ip, f"grafana:{secret}@")
        client(denied_ip, f"grafana:{secret}@")
        client(allowed_ip, "grafana:WrongPassword9@")
        client(allowed_ip, "")
        entries = _acl_entries(name, expected=4)
        codes = {(item.client, item.code) for item in entries}
        assert (denied_ip, 3) in codes
        assert (allowed_ip, 6) in codes
        assert (allowed_ip, 4) in codes
        allowed = [item.code for item in entries if item.client == allowed_ip and item.user == "grafana"]
        assert any(code not in {1, 3, 4, 5, 6} for code in allowed), entries
        logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True, timeout=20)
        assert secret not in logs.stdout + logs.stderr
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True)
        subprocess.run(["docker", "network", "rm", network], capture_output=True, text=True)


def _acl_entries(name: str, expected: int) -> list:
    from proxycli.services.proxyacl import parse_log

    deadline = time.time() + 30
    entries: list = []
    while time.time() < deadline:
        logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True, timeout=20)
        entries = parse_log(logs.stdout + logs.stderr, 1080)
        if len(entries) >= expected:
            return entries
        time.sleep(1)
    return entries


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
