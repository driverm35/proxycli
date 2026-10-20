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
from proxycli.services.probes import LayerResult, ProbeReport, probe_upstream
from proxycli.services.proxy3cfg import render_3proxy
from proxycli.ui.console import CLEARTEXT_WARNING, curl_example, format_user_list, reveal_user
from proxycli.ui.status import plain_status, unicode_disabled
from proxycli.utils.proc import ProcResult, SubprocessRunner
from proxycli.utils.validation import (
    join_upstream_path,
    upstream_rewrite_prefix,
    validate_domain,
    validate_subdomain,
    validate_upstream,
)

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
        validate_upstream("https://example.com/hook\n/admin")
    with pytest.raises(ValidationError):
        validate_upstream("https://user:pass@example.com/hook/")
    with pytest.raises(ValidationError):
        validate_upstream("https://example.com/%24(id)")
    with pytest.raises(ValidationError):
        validate_domain("hooks.example.com`id`")
    with pytest.raises(ValidationError):
        SubprocessRunner()(["echo", "a\nb"])


WEBHOOK_BASE = "/admin/admin_api/telegram/webhook"
WEBHOOK_UPSTREAM = f"https://api.stage.dddevspace.ru{WEBHOOK_BASE}/"


def test_upstream_accepts_base_path_and_port():
    with pytest.raises(ValidationError, match="upstream должен начинаться с http:// или https://"):
        validate_upstream("api.stage.dddevspace.ru/admin/admin_api/telegram/webhook/")
    assert validate_upstream(WEBHOOK_UPSTREAM) == WEBHOOK_UPSTREAM
    assert validate_upstream(WEBHOOK_UPSTREAM.rstrip("/")) == WEBHOOK_UPSTREAM.rstrip("/")
    assert (
        validate_upstream("https://API.Stage.dddevspace.ru:443/admin/admin_api/telegram/webhook/")
        == WEBHOOK_UPSTREAM
    )
    assert validate_upstream("https://api.example.com:8443/hook") == "https://api.example.com:8443/hook"
    assert validate_upstream("https://example.com/") == "https://example.com"
    assert validate_upstream(validate_upstream(WEBHOOK_UPSTREAM)) == WEBHOOK_UPSTREAM
    with pytest.raises(ValidationError, match="логин или пароль"):
        validate_upstream("https://@example.com/hook")
    with pytest.raises(ValidationError):
        validate_upstream("https://bad_host.example/hook")
    with pytest.raises(ValidationError, match="SSH"):
        validate_upstream("https://example.com:22/hook")


def test_join_upstream_path_slash_and_query():
    for base in (WEBHOOK_BASE + "/", WEBHOOK_BASE):
        assert join_upstream_path(base, "/") == "/admin/admin_api/telegram/webhook/"
        assert join_upstream_path(base, "/extra?x=1") == "/admin/admin_api/telegram/webhook/extra?x=1"
        assert "//" not in join_upstream_path(base, "/extra?x=1").split("?", 1)[0]
        prefix = upstream_rewrite_prefix(base)
        assert prefix == WEBHOOK_BASE
        assert prefix + "/" == join_upstream_path(base, "/")
        assert prefix + "/extra?x=1" == join_upstream_path(base, "/extra?x=1")
    assert join_upstream_path("", "/extra?x=1") == "/extra?x=1"
    assert join_upstream_path("/", "/") == "/"
    assert join_upstream_path("/", "/extra?x=1") == "/extra?x=1"


def test_caddyfile_rewrites_base_path_and_leaves_origin_alone():
    for path in (WEBHOOK_BASE + "/", WEBHOOK_BASE):
        config = AppConfig(
            wildcard_domain="hooks.example.com",
            routes=[Route(subdomain="tgadminbot", upstream=f"https://api.stage.dddevspace.ru{path}")],
        )
        text, _warnings = render_caddyfile(config)
        assert "rewrite * /admin/admin_api/telegram/webhook{http.request.uri}" in text
        proxy = next(line.strip() for line in text.splitlines() if line.strip().startswith("reverse_proxy"))
        assert proxy == "reverse_proxy https://api.stage.dddevspace.ru:443 {"
        assert "/admin" not in proxy
        assert "header_up Host {upstream_hostport}" in text
        assert "X-Forwarded-For" in text
        assert "X-Forwarded-Proto" in text
        assert "X-Forwarded-Host" in text
        assert "X-Real-IP" in text
    plain = AppConfig(
        wildcard_domain="hooks.example.com",
        routes=[Route(subdomain="pay", upstream="https://1.1.1.1")],
    )
    text, _warnings = render_caddyfile(plain)
    assert "rewrite" not in text
    assert "reverse_proxy https://1.1.1.1:443 {" in text


def test_base_path_route_is_stored(stack, capsys):
    _wizard()
    assert main(["routes", "add", "--subdomain", "tgadminbot", "--upstream", WEBHOOK_UPSTREAM, "--skip-probes"]) == 0
    route = stack.store.load().route("tgadminbot")
    assert route is not None
    assert route.upstream == WEBHOOK_UPSTREAM
    text = stack.layout.caddyfile.read_text(encoding="utf-8")
    assert "rewrite * /admin/admin_api/telegram/webhook{http.request.uri}" in text
    assert "reverse_proxy https://api.stage.dddevspace.ru/admin" not in text
    captured = capsys.readouterr()
    assert "https://tgadminbot.hooks.example.com" in captured.out
    assert WEBHOOK_UPSTREAM in captured.out
    assert "setWebhook" in captured.out
    assert "только хост" in captured.out


def test_menu_rejects_schemeless_upstream_before_confirm(stack, monkeypatch):
    from proxycli.ui.menu import _routes

    _wizard()
    choices = iter(["add", "back"])
    texts = iter(["pay", "api.stage.dddevspace.ru/admin/admin_api/telegram/webhook/"])
    monkeypatch.setattr("proxycli.ui.menu.choose", lambda *_args, **_kwargs: next(choices))
    monkeypatch.setattr("proxycli.ui.menu.ask_text", lambda *_args, **_kwargs: next(texts))

    def _forbid(*_args, **_kwargs):
        raise AssertionError("вопрос задан до проверки URL")

    monkeypatch.setattr("proxycli.ui.menu.ask_confirm", _forbid)
    with pytest.raises(ValidationError, match="upstream должен начинаться с http:// или https://"):
        _routes(stack)
    assert stack.store.load().route("pay") is None


def test_public_host_does_not_ask_private_confirm(stack, monkeypatch, capsys):
    from proxycli.ui.menu import _routes

    _wizard()
    choices = iter(["add", "back"])
    texts = iter(["tgadminbot", WEBHOOK_UPSTREAM])
    monkeypatch.setattr("proxycli.ui.menu.choose", lambda *_args, **_kwargs: next(choices))
    monkeypatch.setattr("proxycli.ui.menu.ask_text", lambda *_args, **_kwargs: next(texts))

    def _forbid(*_args, **_kwargs):
        raise AssertionError("вопрос trusted-private задан публичному хосту")

    monkeypatch.setattr("proxycli.ui.menu.ask_confirm", _forbid)
    _routes(stack)
    captured = capsys.readouterr()
    assert "trusted-private" not in captured.out
    assert "https://tgadminbot.hooks.example.com" in captured.out
    assert WEBHOOK_UPSTREAM in captured.out
    assert "setWebhook" in captured.out
    assert stack.store.load().route("tgadminbot") is not None


def test_private_host_still_asks_for_trust(stack, monkeypatch):
    from proxycli.ui.menu import _routes

    _wizard()
    choices = iter(["add", "back"])
    texts = iter(["pay", "http://10.1.2.3:8080/hook/"])
    asked: list[str] = []
    monkeypatch.setattr("proxycli.ui.menu.choose", lambda *_args, **_kwargs: next(choices))
    monkeypatch.setattr("proxycli.ui.menu.ask_text", lambda *_args, **_kwargs: next(texts))
    monkeypatch.setattr(
        "proxycli.ui.menu.ask_confirm",
        lambda label, **_kwargs: asked.append(label) or True,
    )
    _routes(stack)
    assert asked == ["Подтвердить приватный апстрим (trusted-private)?"]
    route = stack.store.load().route("pay")
    assert route is not None
    assert route.trust_private is True
    assert route.upstream == "http://10.1.2.3:8080/hook/"


def test_menu_refuses_metadata_without_confirm(stack, monkeypatch):
    from proxycli.ui.menu import _routes

    _wizard()
    choices = iter(["add", "back"])
    texts = iter(["pay", "http://169.254.169.254/latest"])
    monkeypatch.setattr("proxycli.ui.menu.choose", lambda *_args, **_kwargs: next(choices))
    monkeypatch.setattr("proxycli.ui.menu.ask_text", lambda *_args, **_kwargs: next(texts))

    def _forbid(*_args, **_kwargs):
        raise AssertionError("вопрос задан для metadata")

    monkeypatch.setattr("proxycli.ui.menu.ask_confirm", _forbid)
    with pytest.raises(ValidationError, match="metadata"):
        _routes(stack)
    assert stack.store.load().route("pay") is None


def test_forbidden_upstream_ignores_trust(stack):
    _wizard()
    for upstream in (
        "http://127.0.0.1:8080/hook",
        "http://169.254.169.254/latest",
        "http://[::1]/hook",
        "https://metadata.google.internal/path",
        "http://169.254.1.1:8080/hook",
    ):
        assert main([
            "routes", "add", "--subdomain", "pay", "--upstream", upstream,
            "--trust-private", "--skip-probes",
        ]) == 2
        assert stack.store.load().route("pay") is None


def _timeout_report() -> ProbeReport:
    report = ProbeReport()
    report.layers.append(
        LayerResult("tls", "fail", "The handshake operation timed out", "openssl s_client")
    )
    return report


def _alive_report(status: int) -> ProbeReport:
    report = ProbeReport()
    report.layers.append(LayerResult("http", "ok", f"HTTP {status} (ответ есть, маршрут не считается мёртвым)"))
    return report


def test_upstream_auth_and_not_found_are_alive(monkeypatch):
    monkeypatch.setattr("proxycli.services.probes.resolve_ipv4", lambda *_a, **_k: ["93.184.216.34"])
    monkeypatch.setattr("proxycli.services.probes.tcp_open", lambda *_a, **_k: None)
    monkeypatch.setattr("proxycli.services.probes.tls_probe", lambda *_a, **_k: None)
    for status in (401, 403, 404):
        monkeypatch.setattr(
            "proxycli.services.probes.http_status",
            lambda *_a, status=status, **_k: status,
        )
        report = probe_upstream(WEBHOOK_UPSTREAM, 1, trust_private=False)
        assert report.ok, status


def test_tls_handshake_timeout_is_a_failed_probe(monkeypatch):
    monkeypatch.setattr("proxycli.services.probes.resolve_ipv4", lambda *_a, **_k: ["93.184.216.34"])
    monkeypatch.setattr("proxycli.services.probes.tcp_open", lambda *_a, **_k: None)

    def _timeout(*_args, **_kwargs):
        raise ProbeError("The handshake operation timed out", layer="tls", fix="openssl s_client")

    monkeypatch.setattr("proxycli.services.probes.tls_probe", _timeout)
    report = probe_upstream(WEBHOOK_UPSTREAM, 1, trust_private=False)
    assert not report.ok
    failed = report.failed()
    assert failed is not None
    assert failed.layer == "tls"
    assert "handshake" in report.summary()


def test_probe_failure_is_saved_only_with_inactive(layout, monkeypatch):
    runner = _RecordingRunner()
    stack = _online_stack(layout, monkeypatch, runner)
    stack.save_wizard(
        public_ip="8.8.8.8",
        domain="hooks.example.com",
        tls_mode="http",
        acme_email="admin@example.com",
        probe=False,
    )
    monkeypatch.setattr("proxycli.managers.stack.probe_upstream", lambda *_a, **_k: _timeout_report())

    def _public_must_not_roll_back(*_args, **_kwargs):
        raise AssertionError("публичная проверка откатывает неактивный маршрут")

    monkeypatch.setattr("proxycli.managers.stack.probe_public_https", _public_must_not_roll_back)
    with pytest.raises(ProbeError, match="handshake"):
        stack.add_route("tgadminbot", WEBHOOK_UPSTREAM, trust_private=False, probe=True)
    assert stack.store.load().route("tgadminbot") is None
    warnings = stack.add_route(
        "tgadminbot",
        WEBHOOK_UPSTREAM,
        trust_private=False,
        probe=True,
        inactive=True,
    )
    route = stack.store.load().route("tgadminbot")
    assert route is not None
    assert route.upstream == WEBHOOK_UPSTREAM
    assert route.enabled is True
    text = stack.layout.caddyfile.read_text(encoding="utf-8")
    assert "tgadminbot.hooks.example.com" in text
    assert "rewrite * /admin/admin_api/telegram/webhook{http.request.uri}" in text
    assert any("Успех доставки не подтверждён" in item for item in warnings)


def test_http_401_saves_without_inactive(layout, monkeypatch):
    runner = _RecordingRunner()
    stack = _online_stack(layout, monkeypatch, runner)
    stack.save_wizard(
        public_ip="8.8.8.8",
        domain="hooks.example.com",
        tls_mode="http",
        acme_email="admin@example.com",
        probe=False,
    )
    monkeypatch.setattr("proxycli.managers.stack.probe_upstream", lambda *_a, **_k: _alive_report(401))
    ok = ProbeReport()
    ok.layers.extend(
        [
            LayerResult("dns", "ok", "8.8.8.8"),
            LayerResult("tcp", "ok", "8.8.8.8:443"),
            LayerResult("tls", "ok", "сертификат принят"),
            LayerResult("http", "ok", "HTTP 401 (ответ есть, маршрут не считается мёртвым)"),
        ]
    )
    monkeypatch.setattr("proxycli.managers.stack.probe_public_https", lambda *_a, **_k: ok)
    warnings = stack.add_route("pay", "https://example.com/hook/", trust_private=False, probe=True)
    assert not any("не подтверждён" in item for item in warnings)
    route = stack.store.load().route("pay")
    assert route is not None
    assert route.enabled is True


def test_menu_timeout_yes_saves_and_no_does_not_say_error(layout, monkeypatch, capsys):
    from proxycli.ui.menu import _routes

    runner = _RecordingRunner()
    stack = _online_stack(layout, monkeypatch, runner)
    stack.save_wizard(
        public_ip="8.8.8.8",
        domain="hooks.example.com",
        tls_mode="http",
        acme_email="admin@example.com",
        probe=False,
    )
    monkeypatch.setattr("proxycli.managers.stack.probe_upstream", lambda *_a, **_k: _timeout_report())
    choices = iter(["add", "back"])
    texts = iter(["tgadminbot", WEBHOOK_UPSTREAM])
    monkeypatch.setattr("proxycli.ui.menu.choose", lambda *_args, **_kwargs: next(choices))
    monkeypatch.setattr("proxycli.ui.menu.ask_text", lambda *_args, **_kwargs: next(texts))
    monkeypatch.setattr("proxycli.ui.menu.ask_confirm", lambda *_args, **_kwargs: False)
    _routes(stack)
    declined = capsys.readouterr().out
    assert "Маршрут не сохранён." in declined
    assert "Ошибка:" not in declined
    assert "Предупреждение:" in declined
    assert stack.store.load().route("tgadminbot") is None

    choices = iter(["add", "back"])
    texts = iter(["tgadminbot", WEBHOOK_UPSTREAM])
    monkeypatch.setattr("proxycli.ui.menu.choose", lambda *_args, **_kwargs: next(choices))
    monkeypatch.setattr("proxycli.ui.menu.ask_text", lambda *_args, **_kwargs: next(texts))
    monkeypatch.setattr("proxycli.ui.menu.ask_confirm", lambda *_args, **_kwargs: True)
    _routes(stack)
    accepted = capsys.readouterr().out
    assert "Ошибка:" not in accepted
    assert "https://tgadminbot.hooks.example.com" in accepted
    assert WEBHOOK_UPSTREAM in accepted
    assert "setWebhook" in accepted
    assert stack.store.load().route("tgadminbot") is not None
    text = stack.layout.caddyfile.read_text(encoding="utf-8")
    assert "rewrite * /admin/admin_api/telegram/webhook{http.request.uri}" in text


def test_cli_inactive_flag_keeps_route(layout, monkeypatch, capsys):
    runner = _RecordingRunner()
    stack = _online_stack(layout, monkeypatch, runner)
    stack.save_wizard(
        public_ip="8.8.8.8",
        domain="hooks.example.com",
        tls_mode="http",
        acme_email="admin@example.com",
        probe=False,
    )
    monkeypatch.setattr("proxycli.managers.stack.probe_upstream", lambda *_a, **_k: _timeout_report())
    monkeypatch.setattr("proxycli.cli.Stack", lambda: stack)
    assert main(["routes", "add", "--subdomain", "tgadminbot", "--upstream", WEBHOOK_UPSTREAM]) == 1
    assert stack.store.load().route("tgadminbot") is None
    error = capsys.readouterr().err
    assert "Ошибка:" in error
    assert main([
        "routes", "add", "--subdomain", "tgadminbot", "--upstream", WEBHOOK_UPSTREAM, "--inactive",
    ]) == 0
    assert stack.store.load().route("tgadminbot") is not None
    saved = capsys.readouterr().out
    assert WEBHOOK_UPSTREAM in saved
    assert "https://tgadminbot.hooks.example.com" in saved


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


def test_user_list_masks_password_and_reveal_shows_it(stack):
    socks_password = "GrafanaSecret99"
    http_password = "HttpProxySecret1"
    config = AppConfig(
        public_ipv4="203.0.113.8",
        first_run_complete=True,
        socks=Listener(
            enabled=True,
            port=1080,
            allowlist=["203.0.113.10"],
            users=[
                ProxyUser("grafana", "socks:grafana"),
                ProxyUser("alice", "socks:alice"),
            ],
        ),
        http=Listener(
            enabled=False,
            port=3128,
            users=[ProxyUser("grafana", "http:grafana")],
        ),
    )
    stack.store.save(config)
    stack.store.save_secrets(
        {
            "socks:grafana": socks_password,
            "socks:alice": "AlicePassword1",
            "http:grafana": http_password,
        }
    )
    loaded = stack.store.load()
    secrets = stack.store.load_secrets()
    assert stack.layout.secrets_file.is_file()
    assert socks_password in stack.layout.secrets_file.read_text(encoding="utf-8")

    listed = format_user_list("socks", loaded)
    assert "grafana" in listed
    assert "alice" in listed
    assert "1080" in listed
    assert "включён" in listed
    assert "203.0.113.10" in listed
    assert "пароль: ****" in listed
    assert socks_password not in listed
    assert http_password not in listed
    assert "AlicePassword1" not in listed

    http_listed = format_user_list("http", loaded)
    assert "grafana" in http_listed
    assert "3128" in http_listed
    assert "заблокирован" in http_listed
    assert "allowlist" not in http_listed
    assert http_password not in http_listed
    assert socks_password not in http_listed

    shown = reveal_user("socks", "grafana", loaded, secrets)
    assert socks_password in shown
    assert "203.0.113.8" in shown
    assert "1080" in shown
    assert "grafana" in shown
    assert "Скопируйте" in shown
    assert f"socks5://grafana:{socks_password}@203.0.113.8:1080" in shown
    assert http_password not in shown
    assert "AlicePassword1" not in shown

    http_shown = reveal_user("http", "grafana", loaded, secrets)
    assert http_password in http_shown
    assert "3128" in http_shown
    assert "203.0.113.8" in http_shown
    assert socks_password not in http_shown

    unknown = reveal_user("socks", "nobody", loaded, secrets)
    assert "не найден" in unknown
    assert socks_password not in unknown
    assert http_password not in unknown

    empty = reveal_user("socks", "grafana", loaded, {})
    assert "пуст" in empty
    assert socks_password not in empty

    missing_file = reveal_user("socks", "grafana", loaded, None)
    assert "отсутств" in missing_file
    assert socks_password not in missing_file

    missing_key = reveal_user("socks", "grafana", loaded, {"http:grafana": http_password})
    assert "не найден" in missing_key
    assert socks_password not in missing_key
    assert http_password not in missing_key

    assert "нет" in format_user_list("socks", AppConfig())
    log_path = stack.layout.events_file
    log_text = log_path.read_text(encoding="utf-8") if log_path.exists() else ""
    assert socks_password not in log_text
    assert http_password not in log_text


def test_user_menu_holds_list_and_prints_password(stack, monkeypatch, capsys):
    from proxycli.ui.menu import _users

    socks_password = "GrafanaSecret99"
    http_password = "HttpProxySecret1"
    config = AppConfig(
        public_ipv4="203.0.113.8",
        first_run_complete=True,
        socks=Listener(
            enabled=True,
            port=1080,
            allowlist=["198.51.100.20"],
            users=[ProxyUser("grafana", "socks:grafana")],
        ),
        http=Listener(
            enabled=True,
            port=3128,
            users=[ProxyUser("bob", "http:bob")],
        ),
    )
    stack.store.save(config)
    stack.store.save_secrets({"socks:grafana": socks_password, "http:bob": http_password})
    holds: list[str] = []
    monkeypatch.setattr("proxycli.ui.menu.pause", lambda: holds.append("hold"))
    monkeypatch.setattr("proxycli.ui.menu.copy_secret", lambda *_args, **_kwargs: True)

    def run(kind: str, choices: list[str], names: list[str]) -> str:
        picked = iter(choices)
        asked = iter(names)
        monkeypatch.setattr("proxycli.ui.menu.choose", lambda *_args, **_kwargs: next(picked))
        monkeypatch.setattr("proxycli.ui.menu.ask_text", lambda *_args, **_kwargs: next(asked))
        before = len(holds)
        _users(stack, kind)
        assert len(holds) > before
        return capsys.readouterr().out

    socks_list = run("socks", ["list", "back"], [])
    assert "grafana" in socks_list
    assert "1080" in socks_list
    assert "включён" in socks_list
    assert "198.51.100.20" in socks_list
    assert "****" in socks_list
    assert socks_password not in socks_list
    assert http_password not in socks_list

    socks_reveal = run("socks", ["reveal", "back"], ["grafana"])
    assert socks_password in socks_reveal
    assert "203.0.113.8" in socks_reveal
    assert "1080" in socks_reveal
    assert "grafana" in socks_reveal
    assert "Скопируйте" in socks_reveal
    assert http_password not in socks_reveal

    unknown = run("socks", ["reveal", "back"], ["missing"])
    assert "не найден" in unknown
    assert socks_password not in unknown

    http_list = run("http", ["list", "back"], [])
    assert "bob" in http_list
    assert "3128" in http_list
    assert http_password not in http_list
    assert socks_password not in http_list

    http_reveal = run("http", ["reveal", "back"], ["bob"])
    assert http_password in http_reveal
    assert socks_password not in http_reveal

    stack.layout.secrets_file.unlink()
    missing = run("socks", ["reveal", "back"], ["grafana"])
    assert "отсутств" in missing
    assert socks_password not in missing

    stack.store.save_secrets({})
    empty = run("http", ["reveal", "back"], ["bob"])
    assert "пуст" in empty
    assert http_password not in empty

    log_text = stack.layout.events_file.read_text(encoding="utf-8")
    assert socks_password not in log_text
    assert http_password not in log_text
    assert "socks.reveal" in log_text
    assert "http.reveal" in log_text


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
    assert "--address" in reload
    assert "127.0.0.1:2019" in reload
    assert not any("localhost" in part for part in reload)
    assert not any("--force-recreate" in part for call in runner.calls for part in call)
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
    text = str(caught.value)
    assert "Домен не сохранён" in text
    assert "Caddy не запускался" in text
    assert "sudo proxycli" in text
    assert "proxycli-check.hooks.example.com" in text
    assert "docker" not in text
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
        "proxycli.ui.wizard.check_name_dns",
        lambda *_args, **_kwargs: (False, "имя не указывает на сервер"),
    )
    monkeypatch.setattr(
        "proxycli.managers.stack.check_name_dns",
        lambda *_args, **_kwargs: (False, "имя не указывает на сервер"),
    )
    assert run_wizard(stack) == 1
    captured = capsys.readouterr()
    assert "Домен не сохранён" in captured.out
    assert "Caddy не запускался" in captured.out
    assert "не изменялся" in captured.out
    assert "sudo proxycli" in captured.out
    assert "команда завершилась с ошибкой" not in captured.out
    assert "docker compose" not in captured.out
    assert runner.calls == []
    assert stack.store.load().wildcard_domain == ""


def test_wizard_dns_match_does_not_ask(layout, monkeypatch, capsys):
    from proxycli.ui.wizard import run_wizard

    runner = _RecordingRunner()
    stack = _online_stack(layout, monkeypatch, runner)
    answers = iter(["8.8.8.8", "hooks.example.com", "admin@example.com"])
    monkeypatch.setattr("proxycli.ui.wizard.ask_text", lambda *_args, **_kwargs: next(answers))
    monkeypatch.setattr("proxycli.ui.wizard.choose", lambda *_args, **_kwargs: "http")
    monkeypatch.setattr("proxycli.ui.wizard.detect_public_ipv4", lambda *_args, **_kwargs: "")

    def _forbid_confirm(*_args, **_kwargs):
        raise AssertionError("вопрос DNS задан, хотя проверка совпала")

    monkeypatch.setattr("proxycli.ui.wizard.ask_confirm", _forbid_confirm)
    matched = (True, "proxycli-check.hooks.example.com указывает на 8.8.8.8")
    monkeypatch.setattr("proxycli.ui.wizard.check_name_dns", lambda *_args, **_kwargs: matched)
    monkeypatch.setattr("proxycli.managers.stack.check_name_dns", lambda *_args, **_kwargs: matched)
    assert run_wizard(stack) == 0
    captured = capsys.readouterr()
    assert "Мастер сохранён" in captured.out
    assert "Продолжить, даже если проверка DNS" not in captured.out
    reload = next(call for call in runner.calls if "reload" in call)
    assert "127.0.0.1:2019" in reload
    assert not any("localhost" in part for part in reload)
    assert stack.store.load().wildcard_domain == "hooks.example.com"


def test_admin_down_restarts_without_rollback(layout, monkeypatch):
    class _Runner:
        def __init__(self) -> None:
            self.calls: list[list[str]] = []

        def __call__(self, argv: list[str], timeout: float = 30) -> ProcResult:
            self.calls.append(list(argv))
            if "reload" in argv:
                return ProcResult(1, "", "dial tcp 127.0.0.1:2019: connect: connection refused")
            if argv[:2] == ["docker", "inspect"]:
                return ProcResult(0, "running\n", "")
            return ProcResult(0, "", "")

    runner = _Runner()
    stack = _online_stack(layout, monkeypatch, runner)
    warnings = stack.save_wizard(
        public_ip="8.8.8.8",
        domain="hooks.example.com",
        tls_mode="http",
        acme_email="admin@example.com",
        probe=False,
    )
    assert stack.store.load().wildcard_domain == "hooks.example.com"
    assert stack.store.load().first_run_complete is True
    assert any("reload не засчитан" in item for item in warnings)
    reload = next(call for call in runner.calls if "reload" in call)
    assert reload[reload.index("--address") + 1] == "127.0.0.1:2019"
    assert not any("localhost" in part for part in reload)
    assert any("--force-recreate" in call for call in runner.calls)


def test_reload_failure_does_not_keep_domain(layout, monkeypatch, capsys):
    from proxycli.ui.wizard import run_wizard

    class _Runner:
        def __call__(self, argv: list[str], timeout: float = 30) -> ProcResult:
            if "reload" in argv:
                return ProcResult(1, "", "Error: adapting config using caddyfile: bad token")
            if argv[:2] == ["docker", "inspect"]:
                return ProcResult(0, "running\n", "")
            return ProcResult(0, "", "")

    stack = _online_stack(layout, monkeypatch, _Runner())
    answers = iter(["8.8.8.8", "hooks.example.com", "admin@example.com"])
    monkeypatch.setattr("proxycli.ui.wizard.ask_text", lambda *_args, **_kwargs: next(answers))
    monkeypatch.setattr("proxycli.ui.wizard.choose", lambda *_args, **_kwargs: "http")
    monkeypatch.setattr("proxycli.ui.wizard.detect_public_ipv4", lambda *_args, **_kwargs: "")

    def _forbid_confirm(*_args, **_kwargs):
        raise AssertionError("вопрос DNS задан, хотя проверка совпала")

    monkeypatch.setattr("proxycli.ui.wizard.ask_confirm", _forbid_confirm)
    matched = (True, "proxycli-check.hooks.example.com указывает на 8.8.8.8")
    monkeypatch.setattr("proxycli.ui.wizard.check_name_dns", lambda *_args, **_kwargs: matched)
    monkeypatch.setattr("proxycli.managers.stack.check_name_dns", lambda *_args, **_kwargs: matched)
    assert run_wizard(stack) == 1
    captured = capsys.readouterr()
    assert captured.out.count("Домен не сохранён") == 1
    assert "Мастер сохранён" not in captured.out
    assert "bad token" in captured.out
    assert stack.store.load().wildcard_domain == ""
    assert stack.store.load().first_run_complete is False


def test_update_paths_use_opt_proxycli_venv(tmp_path):
    from proxycli.managers.update import select_update_paths, update_path_candidates

    app = tmp_path / "opt" / "proxycli"
    app.mkdir(parents=True)
    (app / ".git").mkdir()
    (app / "pyproject.toml").write_text("[project]\nname = 'proxycli'\n", encoding="utf-8")
    src = app / "src"
    src.mkdir()
    (src / ".git").mkdir()
    (src / "pyproject.toml").write_text("nested\n", encoding="utf-8")
    dot_pip = app / ".venv" / "bin" / "pip"
    dot_pip.parent.mkdir(parents=True)
    dot_pip.write_text("pip\n", encoding="utf-8")
    old_pip = app / "venv" / "bin" / "pip"
    old_pip.parent.mkdir(parents=True)
    old_pip.write_text("old\n", encoding="utf-8")
    etc = tmp_path / "etc" / "proxycli"
    etc.mkdir(parents=True)
    (etc / "config.json").write_text("keep\n", encoding="utf-8")
    (etc / ".git").mkdir()
    (etc / "pyproject.toml").write_text("nope\n", encoding="utf-8")

    apps, pips = update_path_candidates(Path("/opt/proxycli/src"))
    assert apps[0] == Path("/opt/proxycli")
    assert apps[1] == Path("/opt/proxycli/src")
    assert pips[0] == Path("/opt/proxycli/.venv/bin/pip")
    assert pips.index(Path("/opt/proxycli/.venv/bin/pip")) < pips.index(Path("/opt/proxycli/venv/bin/pip"))

    chosen_app, chosen_pip = select_update_paths(
        [Path("/etc/proxycli"), app, src],
        [dot_pip, old_pip],
    )
    assert chosen_app == app
    assert chosen_pip == dot_pip
    assert (etc / "config.json").read_text(encoding="utf-8") == "keep\n"
    with pytest.raises(ProxyCLIError, match="не изменяет /etc/proxycli"):
        select_update_paths([Path("/etc/proxycli")], [dot_pip])


def test_backup_roundtrip(stack):
    _wizard()
    backup_id = stack.backup.create("manual")
    stack.store.save(stack.store.load())
    listed = main(["backup", "list"])
    assert listed == 0
    assert backup_id
    raw = stack.layout.config_file.read_text(encoding="utf-8")
    assert json.loads(raw)["wildcard_domain"] == "hooks.example.com"
