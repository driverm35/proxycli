import json
import socket
import threading
import time
from pathlib import Path

import pytest

from proxycli.cli import main
from proxycli.constants import CADDY_IMAGE, DOCKER_CE_VERSION, THREEPROXY_IMAGE
from proxycli.errors import ProbeError, ProxyCLIError, RollbackError, ValidationError
from proxycli.managers.firewall import command_is_unsafe, plan_apply, plan_rollback
from proxycli.managers.stack import Stack
from proxycli.models.config import AppConfig, Listener, ProxyUser, Route
from proxycli.services.caddyfile import render_caddyfile
from proxycli.services.compose import ENTRYPOINT, render_compose, render_dockerfile
from proxycli.services.proxy3cfg import render_3proxy
from proxycli.ui.console import CLEARTEXT_WARNING, curl_example
from proxycli.ui.status import plain_status, unicode_disabled
from proxycli.utils.proc import ProcResult, SubprocessRunner
from proxycli.utils.validation import validate_domain, validate_subdomain, validate_upstream

ROOT = Path(__file__).resolve().parents[1]


def _wizard(extra=None):
    args = [
        "wizard",
        "--public-ip",
        "8.8.8.8",
        "--domain",
        "hooks.example.com",
        "--tls-mode",
        "http",
        "--acme-email",
        "admin@example.com",
        "--skip-probes",
    ]
    if extra:
        args.extend(extra)
    assert main(args) == 0


def test_rejects_injection():
    with pytest.raises(ValidationError):
        validate_subdomain("pay;rm -rf /")
    with pytest.raises(ValidationError):
        validate_subdomain("pay\n{ admin off }")
    with pytest.raises(ValidationError):
        validate_upstream("https://example.com/$(id)")
    with pytest.raises(ValidationError):
        validate_domain("hooks.example.com`id`")
    with pytest.raises(ValidationError):
        SubprocessRunner()(["echo", "a\nb"])


def test_private_upstream_needs_trust(stack):
    _wizard()
    assert main(["routes", "add", "--subdomain", "pay", "--upstream", "http://10.1.2.3:8080", "--skip-probes"]) == 2
    assert main(["routes", "add", "--subdomain", "pay", "--upstream", "http://10.1.2.3:8080", "--trust-private", "--skip-probes"]) == 0
    text = stack.layout.caddyfile.read_text(encoding="utf-8")
    assert "pay.hooks.example.com" in text
    assert "X-Forwarded-For" in text
    assert "X-Forwarded-Host" in text
    assert "tls_insecure_skip_verify" not in text


def test_route_reload_failure_rolls_back(stack, monkeypatch):
    _wizard()
    monkeypatch.setenv("PROXYCLI_FAIL_STEP", "reload")
    code = main(["routes", "add", "--subdomain", "pay", "--upstream", "https://1.1.1.1", "--skip-probes"])
    assert code == 1
    config = stack.store.load()
    assert config.route("pay") is None
    rendered = stack.layout.caddyfile.read_text(encoding="utf-8")
    assert "pay.hooks.example.com" not in rendered


def test_edit_and_delete(stack, monkeypatch):
    _wizard()
    assert main(["routes", "add", "--subdomain", "pay", "--upstream", "https://1.1.1.1", "--skip-probes"]) == 0
    assert main(["routes", "edit", "--subdomain", "pay", "--upstream", "https://8.8.4.4", "--skip-probes"]) == 0
    assert "8.8.4.4" in stack.layout.caddyfile.read_text(encoding="utf-8")
    monkeypatch.setenv("PROXYCLI_FAIL_STEP", "reload")
    assert main(["routes", "remove", "--subdomain", "pay"]) == 1
    assert stack.store.load().route("pay") is not None
    monkeypatch.delenv("PROXYCLI_FAIL_STEP")
    assert main(["routes", "remove", "--subdomain", "pay"]) == 0
    assert stack.store.load().route("pay") is None


def test_caddy_mode_b_does_not_fake_wildcard(stack):
    token = stack.layout.token_file
    token.write_text("a" * 40, encoding="utf-8")
    assert main([
        "wizard",
        "--public-ip", "8.8.8.8",
        "--domain", "hooks.example.com",
        "--tls-mode", "dns",
        "--acme-email", "admin@example.com",
        "--cloudflare-token-file", str(token),
        "--skip-probes",
    ]) == 0
    config = stack.store.load()
    assert config.tls.mode == "dns"
    assert config.tls.dns_plugin_ready is False
    text, warnings = render_caddyfile(config)
    assert "dns cloudflare" not in text
    assert warnings
    assert "a" * 40 not in text
    ready = AppConfig(
        wildcard_domain="hooks.example.com",
        tls=config.tls,
        routes=[Route(subdomain="pay", upstream="https://1.1.1.1")],
    )
    ready.tls.dns_plugin_ready = True
    wild, wild_warnings = render_caddyfile(ready)
    assert "dns cloudflare {env.CLOUDFLARE_API_TOKEN}" in wild
    assert wild_warnings == []
    assert "a" * 40 not in wild


def test_3proxy_requires_auth_and_blocks_metadata():
    config = AppConfig()
    idle = render_3proxy(config, {})
    assert "auth strong" in idle
    assert "auth none" not in idle
    assert "\nsocks " not in idle
    assert "\nproxy " not in idle
    config.socks = Listener(enabled=True, port=1080, users=[ProxyUser("alice", "socks:alice")])
    config.http = Listener(enabled=True, port=3128, allowlist=["203.0.113.10"], users=[ProxyUser("bob", "http:bob")])
    secrets = {"socks:alice": "AlicePassword1", "http:bob": "BobPassword123"}
    text = render_3proxy(config, secrets)
    assert "auth strong" in text
    assert "auth none" not in text
    assert "allow *" not in text
    assert "127.0.0.0/8" in text
    assert "169.254.169.254" in text
    assert "metadata.google.internal" in text
    assert "alice:CL:AlicePassword1" in text
    assert "socks -p1080 -n -u2" in text
    assert "proxy -p3128 -n -u2" in text
    assert "allow bob 203.0.113.10" in text
    compose = render_compose(config, Path("/etc/proxycli/cloudflare.token"))
    assert "0.0.0.0:1080:1080" in compose
    assert "22:22" not in compose
    assert THREEPROXY_IMAGE in compose
    assert CADDY_IMAGE in render_compose(AppConfig(), Path("/etc/proxycli/cloudflare.token"))


def test_passwords_are_not_logged(stack, capsys):
    _wizard()
    assert main(["socks", "add-user", "--username", "alice", "--password", "AlicePassword1"]) == 0
    captured = capsys.readouterr()
    assert "AlicePassword1" in captured.out
    config_text = stack.layout.config_file.read_text(encoding="utf-8")
    log_text = stack.layout.events_file.read_text(encoding="utf-8")
    assert "AlicePassword1" not in config_text
    assert "AlicePassword1" not in log_text
    assert "AlicePassword1" in stack.layout.proxy_cfg.read_text(encoding="utf-8")
    assert main(["socks", "reveal", "--username", "alice", "--i-understand"]) == 0
    assert "AlicePassword1" not in stack.layout.events_file.read_text(encoding="utf-8")


def test_user_add_rolls_back_secret(stack, monkeypatch):
    _wizard()
    monkeypatch.setenv("PROXYCLI_FAIL_STEP", "reload")
    assert main(["http", "add-user", "--username", "bob", "--password", "BobPassword123"]) == 1
    assert stack.store.load_secrets().get("http:bob") is None
    assert stack.store.load().http.users == []


def test_firewall_is_additive_and_skips_ssh():
    ruleset = {
        "nftables": [
            {"chain": {"family": "inet", "table": "filter", "name": "input", "type": "filter", "hook": "input", "policy": "drop"}},
            {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 4, "comment": "allow-ssh"}},
        ]
    }
    commands, _note = plan_apply(ruleset, [("tcp", 80), ("tcp", 443), ("udp", 443)])
    assert commands
    assert all(not command_is_unsafe(item) for item in commands)
    assert all("flush" not in item for item in commands)
    rollback = plan_rollback(
        {
            "nftables": [
                {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 4, "comment": "allow-ssh"}},
                {"rule": {"family": "inet", "table": "filter", "chain": "input", "handle": 8, "comment": "proxycli-tcp-80"}},
            ]
        }
    )
    assert rollback == [["nft", "delete", "rule", "inet", "filter", "input", "handle", "8"]]
    empty, note = plan_apply({"nftables": []}, [("tcp", 80)])
    assert empty == []
    assert "не изменялся" in note


def test_doctor_and_status(stack):
    assert main(["version"]) == 0
    assert main(["status", "--json"]) == 0
    assert main(["doctor", "--json", "--timeout", "2"]) == 0
    text = plain_status(stack)
    assert "не проверено" in text
    assert "ProxyCLI" in text


def test_doctor_timeout(stack, monkeypatch):
    from proxycli.doctor import CheckResult, run_doctor

    def slow(_stack):
        time.sleep(0.6)
        return CheckResult("Docker", "ok", "late")

    monkeypatch.setattr("proxycli.doctor._docker", slow)
    results = run_doctor(stack, timeout=0.2)
    docker = next(item for item in results if item.name == "Docker")
    assert docker.status == "fail"
    assert "таймаут" in docker.cause or "ожидан" in docker.detail


def test_plain_ui_has_no_box_drawing(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert unicode_disabled()
    assert "┌" not in curl_example("8.8.8.8", 3128, "alice")
    assert "****" in curl_example("8.8.8.8", 3128, "alice")
    assert "открытом виде" in CLEARTEXT_WARNING


def test_shipped_assets_match_renderer():
    empty = AppConfig()
    assert (ROOT / "deploy" / "caddy" / "Caddyfile").read_text(encoding="utf-8").replace("\r\n", "\n") == render_caddyfile(empty)[0]
    assert (ROOT / "deploy" / "3proxy" / "3proxy.cfg").read_text(encoding="utf-8").replace("\r\n", "\n") == render_3proxy(empty, {})
    compose = render_compose(empty, Path("/etc/proxycli/cloudflare.token"))
    assert (ROOT / "deploy" / "compose.yaml").read_text(encoding="utf-8").replace("\r\n", "\n") == compose
    assert (ROOT / "deploy" / "caddy" / "Dockerfile").read_text(encoding="utf-8").replace("\r\n", "\n") == render_dockerfile()
    assert (ROOT / "deploy" / "caddy" / "entrypoint.sh").read_text(encoding="utf-8").replace("\r\n", "\n") == ENTRYPOINT
    install = (ROOT / "install.sh").read_text(encoding="utf-8")
    assert f'CADDY_IMAGE="{CADDY_IMAGE}"' in install
    assert f'THREEPROXY_IMAGE="{THREEPROXY_IMAGE}"' in install
    assert f'DOCKER_CE_VERSION="{DOCKER_CE_VERSION}"' in install
    assert "nft flush ruleset" not in install
    assert "iptables -F" not in install
    assert "sshd_config" not in install
    uninstall = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
    assert "nft flush" not in uninstall
    assert "sshd_config" not in uninstall


def test_socks_and_http_clients():
    socks = socket.socket()
    socks.bind(("127.0.0.1", 0))
    socks.listen(1)
    port = socks.getsockname()[1]

    def serve_socks():
        conn, _addr = socks.accept()
        with conn:
            greeting = conn.recv(8)
            if greeting == b"\x05\x01\x00":
                conn.sendall(b"\x05\xff")
                return
            conn.sendall(b"\x05\x02")
            conn.recv(64)
            conn.sendall(b"\x01\x00")
            conn.recv(64)
            conn.sendall(b"\x05\x02\x00\x01" + b"\x00" * 6)

    thread = threading.Thread(target=serve_socks)
    thread.start()
    from proxycli.services.probes import socks5_noauth_rejected

    assert socks5_noauth_rejected("127.0.0.1", port, 2) is True
    thread.join(2)
    socks.close()

    httpd = socket.socket()
    httpd.bind(("127.0.0.1", 0))
    httpd.listen(1)
    http_port = httpd.getsockname()[1]

    def serve_http():
        conn, _addr = httpd.accept()
        with conn:
            conn.recv(1024)
            conn.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")

    thread = threading.Thread(target=serve_http)
    thread.start()
    from proxycli.services.probes import http_proxy_status

    assert http_proxy_status("127.0.0.1", http_port, "1.1.1.1", 443, 2) == 407
    thread.join(2)
    httpd.close()


class _RecordingRunner:
    def __init__(self, fail_token: str = "") -> None:
        self.calls: list[list[str]] = []
        self.fail_token = fail_token

    def __call__(self, argv: list[str], timeout: float = 30) -> ProcResult:
        self.calls.append(list(argv))
        if self.fail_token and self.fail_token in argv:
            return ProcResult(1, "", 'exec: "validate": executable file not found in $PATH')
        return ProcResult(0, "", "")


def _online_stack(layout, monkeypatch, runner):
    monkeypatch.delenv("PROXYCLI_OFFLINE", raising=False)
    return Stack(layout, runner)


def test_caddy_validate_argv_invokes_caddy(layout, monkeypatch):
    runner = _RecordingRunner()
    stack = _online_stack(layout, monkeypatch, runner)
    stack.save_wizard(
        public_ip="8.8.8.8",
        domain="hooks.example.com",
        tls_mode="http",
        acme_email="admin@example.com",
        probe=False,
    )
    validate = next(call for call in runner.calls if "validate" in call)
    image_at = validate.index(CADDY_IMAGE)
    assert validate[image_at + 1 : image_at + 3] == ["caddy", "validate"]
    assert "--entrypoint" not in validate
    reload = next(call for call in runner.calls if "reload" in call)
    assert reload[reload.index("reload") - 1] == "caddy"
    modules = [call for call in runner.calls if "list-modules" in call]
    assert modules == []


def test_validate_failure_reports_command_not_rollback(layout, monkeypatch):
    runner = _RecordingRunner(fail_token="validate")
    stack = _online_stack(layout, monkeypatch, runner)
    with pytest.raises(ProxyCLIError) as caught:
        stack.save_wizard(
            public_ip="8.8.8.8",
            domain="hooks.example.com",
            tls_mode="http",
            acme_email="admin@example.com",
            probe=False,
        )
    error = caught.value
    assert not isinstance(error, RollbackError)
    text = str(error)
    assert "откат не удался" not in text
    assert "caddy validate" in text
    assert "executable file not found" in text
    assert not error.fix.startswith("proxycli backup restore")
    assert "не обязательно" in text
    assert stack.store.load().wildcard_domain == ""
    assert stack.store.load().first_run_complete is False
    assert runner.calls
    assert all(call[call.index(CADDY_IMAGE) + 1] != "validate" for call in runner.calls if CADDY_IMAGE in call)


def test_dns_decline_stops_before_docker(layout, monkeypatch):
    runner = _RecordingRunner()
    stack = _online_stack(layout, monkeypatch, runner)
    monkeypatch.setattr(
        "proxycli.managers.stack.check_name_dns",
        lambda *_args, **_kwargs: (False, "имя не указывает на сервер"),
    )
    with pytest.raises(ProbeError) as caught:
        stack.save_wizard(
            public_ip="8.8.8.8",
            domain="hooks.example.com",
            tls_mode="http",
            acme_email="admin@example.com",
            accept_dns=False,
            probe=True,
        )
    assert "Домен не сохранён" in str(caught.value)
    assert "Caddy не запускался" in str(caught.value)
    assert runner.calls == []
    assert stack.store.load().wildcard_domain == ""
    assert stack.store.load().first_run_complete is False


def test_dns_mismatch_continues_only_when_accepted(layout, monkeypatch):
    runner = _RecordingRunner()
    stack = _online_stack(layout, monkeypatch, runner)
    monkeypatch.setattr(
        "proxycli.managers.stack.check_name_dns",
        lambda *_args, **_kwargs: (False, "имя не указывает на сервер"),
    )
    stack.save_wizard(
        public_ip="8.8.8.8",
        domain="hooks.example.com",
        tls_mode="http",
        acme_email="admin@example.com",
        accept_dns=True,
        probe=True,
    )
    assert any("validate" in call for call in runner.calls)
    assert stack.store.load().wildcard_domain == "hooks.example.com"


def test_wizard_ui_dns_decline_does_not_start_caddy(layout, monkeypatch, capsys):
    from proxycli.ui.wizard import run_wizard

    runner = _RecordingRunner()
    stack = _online_stack(layout, monkeypatch, runner)
    answers = iter(["8.8.8.8", "hooks.example.com", "admin@example.com"])
    monkeypatch.setattr("proxycli.ui.wizard.ask_text", lambda *_args, **_kwargs: next(answers))
    monkeypatch.setattr("proxycli.ui.wizard.choose", lambda *_args, **_kwargs: "http")
    monkeypatch.setattr("proxycli.ui.wizard.ask_confirm", lambda *_args, **_kwargs: False)
    monkeypatch.setattr("proxycli.ui.wizard.detect_public_ipv4", lambda *_args, **_kwargs: "")
    monkeypatch.setattr(
        "proxycli.managers.stack.check_name_dns",
        lambda *_args, **_kwargs: (False, "имя не указывает на сервер"),
    )
    assert run_wizard(stack) == 1
    captured = capsys.readouterr()
    assert "Домен не сохранён" in captured.out
    assert runner.calls == []
    assert stack.store.load().wildcard_domain == ""


def test_backup_roundtrip(stack):
    _wizard()
    backup_id = stack.backup.create("manual")
    stack.store.save(stack.store.load())
    listed = main(["backup", "list"])
    assert listed == 0
    assert backup_id
    raw = stack.layout.config_file.read_text(encoding="utf-8")
    assert json.loads(raw)["wildcard_domain"] == "hooks.example.com"
