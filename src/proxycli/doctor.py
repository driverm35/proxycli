from __future__ import annotations

import os
import shutil
from dataclasses import dataclass

from proxycli.constants import CADDY_CONTAINER, PROXY_CONTAINER
from proxycli.errors import ProbeError, ProxyCLIError
from proxycli.managers.firewall import managed_ports, parse_ruleset, plan_apply
from proxycli.managers.stack import Stack
from proxycli.services.caddyfile import effective_dns
from proxycli.services.probes import (
    http_proxy_status,
    probe_public_https,
    probe_upstream,
    socks5_noauth_rejected,
)
from proxycli.services.store import file_mode
from proxycli.utils.proc import require_ok
from proxycli.utils.timeouts import call_with_timeout
from proxycli.utils.validation import validate_domain, validate_upstream


@dataclass
class CheckResult:
    name: str
    status: str
    detail: str
    cause: str = ""
    fix: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "cause": self.cause,
            "fix": self.fix,
        }


def run_doctor(stack: Stack, timeout: float = 5.0) -> list[CheckResult]:
    checks = [
        ("Конфигурация", lambda: _config(stack)),
        ("Секреты", lambda: _secrets(stack)),
        ("Docker", lambda: _docker(stack)),
        ("Caddy", lambda: _container(stack, CADDY_CONTAINER, "Caddy")),
        ("3proxy", lambda: _proxy_container(stack)),
        ("Порты", lambda: _ports(stack)),
        ("Firewall", lambda: _firewall(stack)),
        ("DNS", lambda: _dns(stack, timeout)),
        ("Сертификаты", lambda: _certs(stack, timeout)),
        ("Upstreams", lambda: _upstreams(stack, timeout)),
        ("SOCKS5", lambda: _socks(stack, timeout)),
        ("HTTP CONNECT", lambda: _http(stack, timeout)),
        ("Автозапуск", lambda: _autostart(stack)),
        ("Диск", lambda: _disk(stack)),
    ]
    results: list[CheckResult] = []
    for name, func in checks:
        try:
            results.append(call_with_timeout(func, timeout))
        except TimeoutError as exc:
            results.append(
                CheckResult(
                    name,
                    "fail",
                    f"таймаут: {exc}",
                    "проверка не уложилась в таймаут",
                    "повторите proxycli doctor",
                )
            )
        except (ProxyCLIError, ProbeError, OSError, ValueError) as exc:
            fix = getattr(exc, "fix", "")
            results.append(CheckResult(name, "fail", str(exc), "ошибка проверки", fix))
    return results


def _config(stack: Stack) -> CheckResult:
    config = stack.store.load()
    if not config.first_run_complete:
        return CheckResult(
            "Конфигурация",
            "warn",
            "мастер не завершён",
            "нет публичного IP и домена",
            "proxycli wizard --help",
        )
    validate_domain(config.wildcard_domain)
    if config.socks.port == config.http.port:
        return CheckResult("Конфигурация", "fail", "SOCKS5 и HTTP используют один порт", "", "смените порт")
    for route in config.routes:
        validate_upstream(route.upstream)
    if config.tls.mode == "dns" and not effective_dns(config):
        return CheckResult(
            "Конфигурация",
            "warn",
            "запрошен режим B, но wildcard TLS не активен",
            "модуль Cloudflare не подтверждён",
            "proxycli settings prepare-dns",
        )
    return CheckResult("Конфигурация", "ok", f"{len(config.routes)} маршрутов, домен {config.wildcard_domain}")


def _secrets(stack: Stack) -> CheckResult:
    config_text = ""
    if stack.layout.config_file.exists():
        config_text = stack.layout.config_file.read_text(encoding="utf-8")
    secrets = stack.store.load_secrets()
    for value in secrets.values():
        if value and value in config_text:
            return CheckResult("Секреты", "fail", "секрет попал в config.json", "пароль записан в открытый конфиг", "уберите секрет и смените пароль")
    if not stack.layout.secrets_file.exists():
        return CheckResult("Секреты", "ok", "файла секретов ещё нет")
    mode = file_mode(stack.layout.secrets_file)
    if mode is not None and mode != 0o600:
        return CheckResult("Секреты", "fail", f"режим {mode:o}", "файл доступен шире, чем владельцу", "chmod 600 secrets.json")
    return CheckResult("Секреты", "ok", "секреты отдельно от config.json")


def _docker(stack: Stack) -> CheckResult:
    if stack.offline():
        return _skip("Docker")
    result = stack.runner(["docker", "info"], timeout=8)
    if not result.ok:
        return CheckResult("Docker", "fail", "docker info неуспешен", "демон не запущен", "systemctl status docker")
    return CheckResult("Docker", "ok", "демон отвечает")


def _container(stack: Stack, name: str, title: str) -> CheckResult:
    if stack.offline():
        return _skip(title)
    state = stack.container_state(name)
    if state == "running":
        return CheckResult(title, "ok", "running")
    return CheckResult(title, "fail", state, "контейнер не в состоянии running", "docker ps -a --filter name=" + name)


def _proxy_container(stack: Stack) -> CheckResult:
    config = stack.store.load()
    needed = (config.socks.enabled and config.socks.users) or (config.http.enabled and config.http.users)
    if not needed:
        return CheckResult("3proxy", "skip", "прокси без пользователей не запускается")
    return _container(stack, PROXY_CONTAINER, "3proxy")


def _ports(stack: Stack) -> CheckResult:
    if stack.offline():
        return _skip("Порты")
    import socket

    config = stack.store.load()
    targets = [80, 443]
    if config.socks.enabled:
        targets.append(config.socks.port)
    if config.http.enabled:
        targets.append(config.http.port)
    closed = []
    for port in targets:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                pass
        except OSError:
            closed.append(str(port))
    if closed:
        return CheckResult("Порты", "fail", "не слушаются: " + ", ".join(closed), "процесс не привязан к порту", "docker ps")
    return CheckResult("Порты", "ok", "локальные порты отвечают")


def _firewall(stack: Stack) -> CheckResult:
    if stack.offline():
        return _skip("Firewall")
    try:
        result = require_ok(stack.runner(["nft", "-j", "list", "ruleset"], timeout=8), ["nft"])
    except ProxyCLIError as exc:
        return CheckResult("Firewall", "warn", str(exc), "nft недоступен", "sudo nft -j list ruleset")
    _commands, note = plan_apply(parse_ruleset(result.stdout), managed_ports(stack.store.load()))
    if note.startswith("Цепочка"):
        return CheckResult(
            "Firewall",
            "warn",
            note,
            "вход не фильтруется drop-политикой",
            "настройте firewall провайдера отдельно; ProxyCLI его не сбрасывает",
        )
    if note.startswith("правила proxycli уже"):
        return CheckResult("Firewall", "ok", note)
    return CheckResult(
        "Firewall",
        "warn",
        note or "есть недостающие правила proxycli",
        "порты могут быть закрыты",
        "proxycli firewall apply",
    )


def _dns(stack: Stack, timeout: float) -> CheckResult:
    config = stack.store.load()
    if not config.routes:
        return CheckResult("DNS", "skip", "маршрутов нет")
    if stack.offline():
        return _skip("DNS")
    problems = []
    for route in config.routes:
        report = probe_public_https(config.hostname(route.subdomain), config.public_ipv4, min(timeout, 3))
        dns = next((item for item in report.layers if item.layer == "dns"), None)
        if dns is None or dns.status != "ok":
            problems.append(config.hostname(route.subdomain))
    if problems:
        return CheckResult("DNS", "fail", "нет ожидаемой A-записи: " + ", ".join(problems), "имя не указывает на VPS", "создайте A-запись на публичный IPv4")
    return CheckResult("DNS", "ok", "A-записи маршрутов совпали с публичным IPv4")


def _certs(stack: Stack, timeout: float) -> CheckResult:
    config = stack.store.load()
    if not config.routes:
        return CheckResult("Сертификаты", "skip", "маршрутов нет")
    if stack.offline():
        return _skip("Сертификаты")
    failed = []
    for route in config.routes:
        report = probe_public_https(config.hostname(route.subdomain), config.public_ipv4, min(timeout, 3))
        tls = next((item for item in report.layers if item.layer == "tls"), None)
        if tls is None or tls.status != "ok":
            failed.append(config.hostname(route.subdomain))
    if failed:
        detail = "TLS не подтверждён: " + ", ".join(failed)
        if config.tls.mode == "dns" and not effective_dns(config):
            detail += ". Wildcard TLS не заявляется."
        return CheckResult("Сертификаты", "fail", detail, "сертификат не выпущен или имя не совпало", "проверьте DNS и порты 80/443; не считайте TLS успешным")
    mode = "wildcard DNS-01" if effective_dns(config) else "сертификат на каждый хост"
    return CheckResult("Сертификаты", "ok", mode)


def _upstreams(stack: Stack, timeout: float) -> CheckResult:
    config = stack.store.load()
    if not config.routes:
        return CheckResult("Upstreams", "skip", "маршрутов нет")
    if stack.offline():
        return _skip("Upstreams")
    bad = []
    for route in config.routes:
        report = probe_upstream(route.upstream, min(timeout, 3), trust_private=route.trust_private)
        if not report.ok:
            bad.append(f"{route.subdomain} ({report.summary()})")
    if bad:
        return CheckResult("Upstreams", "fail", "; ".join(bad), "upstream не прошёл DNS/TCP/TLS/HTTP", "proxycli routes check --subdomain NAME")
    return CheckResult("Upstreams", "ok", f"проверено: {len(config.routes)}")


def _socks(stack: Stack, timeout: float) -> CheckResult:
    config = stack.store.load()
    if not (config.socks.enabled and config.socks.users):
        return CheckResult("SOCKS5", "skip", "не включён")
    if stack.offline():
        return _skip("SOCKS5")
    try:
        rejected = socks5_noauth_rejected("127.0.0.1", config.socks.port, min(timeout, 3))
    except ProbeError as exc:
        return CheckResult("SOCKS5", "fail", exc.message, "порт не прошёл рукопожатие", exc.fix)
    if not rejected:
        return CheckResult("SOCKS5", "fail", "анонимный вход принят", "auth none или allow *", "перегенерируйте 3proxy, пароль обязателен")
    return CheckResult("SOCKS5", "ok", "анонимный метод отклонён")


def _http(stack: Stack, timeout: float) -> CheckResult:
    config = stack.store.load()
    if not (config.http.enabled and config.http.users):
        return CheckResult("HTTP CONNECT", "skip", "не включён")
    if stack.offline():
        return _skip("HTTP CONNECT")
    try:
        status = http_proxy_status("127.0.0.1", config.http.port, "1.1.1.1", 443, min(timeout, 3))
    except ProbeError as exc:
        return CheckResult("HTTP CONNECT", "fail", exc.message, "прокси не ответил", exc.fix)
    if status == 407:
        return CheckResult("HTTP CONNECT", "ok", "без пароля ответ 407; трафик в открытом виде")
    if status == 200:
        return CheckResult("HTTP CONNECT", "fail", "CONNECT без пароля успешен", "анонимный прокси", "включите auth strong")
    return CheckResult("HTTP CONNECT", "warn", f"код {status}", "ожидался 407", "docker logs proxycli-3proxy")


def _autostart(stack: Stack) -> CheckResult:
    if stack.offline():
        return _skip("Автозапуск")
    policy = stack.restart_policy(CADDY_CONTAINER)
    if policy == "unless-stopped":
        return CheckResult("Автозапуск", "ok", "restart=unless-stopped")
    return CheckResult(
        "Автозапуск",
        "fail",
        f"политика: {policy}",
        "контейнер не переживёт перезагрузку так, как задумано",
        "docker update --restart unless-stopped proxycli-caddy",
    )


def _disk(stack: Stack) -> CheckResult:
    path = stack.layout.backup_dir if stack.layout.backup_dir.exists() else stack.layout.config_file.parent
    path.mkdir(parents=True, exist_ok=True)
    usage = shutil.disk_usage(path)
    free_mb = usage.free // (1024 * 1024)
    if free_mb < 100:
        return CheckResult("Диск", "fail", f"свободно {free_mb} МиБ", "мало места для образов и сертификатов", "df -h")
    if free_mb < 500:
        return CheckResult("Диск", "warn", f"свободно {free_mb} МиБ", "место заканчивается", "df -h")
    return CheckResult("Диск", "ok", f"свободно {free_mb} МиБ")


def _skip(name: str) -> CheckResult:
    reason = "PROXYCLI_OFFLINE" if os.environ.get("PROXYCLI_OFFLINE") == "1" else "offline"
    return CheckResult(name, "skip", f"не проверено ({reason}), успех не заявляется")
