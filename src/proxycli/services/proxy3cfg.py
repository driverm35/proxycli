from __future__ import annotations

from proxycli.models.config import AppConfig, Listener
from proxycli.utils.net import BLOCKED_NETS
from proxycli.utils.validation import validate_password, validate_username

BLOCKED_HOST_DENIES = (
    "localhost",
    "metadata.google.internal",
    "metadata.google.com",
    "metadata",
    "instance-data",
)


def render_3proxy(config: AppConfig, secrets: dict[str, str]) -> str:
    socks_on = _active(config.socks)
    http_on = _active(config.http)
    if not socks_on and not http_on:
        text = _idle_config()
        assert_proxy_safe(text, config)
        return text
    lines = [
        "nserver 1.1.1.1",
        "nserver 8.8.8.8",
        "nscache 65536",
        "timeouts 1 5 30 60 180 1800 15 60",
        "maxconn 200",
        "log",
    ]
    if socks_on:
        lines.extend(_acl(config.socks, "socks", secrets))
        lines.append(f"socks -p{config.socks.port} -n")
    if http_on:
        if socks_on:
            lines.append("flush")
        lines.extend(_acl(config.http, "http", secrets))
        lines.append(f"proxy -p{config.http.port} -n")
    text = "\n".join(lines) + "\n"
    assert_proxy_safe(text, config)
    return text


def assert_proxy_safe(text: str, config: AppConfig) -> None:
    if "auth none" in text or "\nallow *" in f"\n{text}" or text.startswith("allow *"):
        raise ValueError("конфигурация открыла бы анонимный прокси")
    if _active(config.socks) or _active(config.http):
        if "auth strong" not in text:
            raise ValueError("нет auth strong")
        if "127.0.0.0/8" not in text or "169.254.0.0/16" not in text:
            raise ValueError("нет запрета SSRF-сетей")
        if "metadata.google.internal" not in text:
            raise ValueError("нет запрета metadata hostname")
        if "socks " in text and not _active(config.socks):
            raise ValueError("SOCKS5 слушает без пользователей")
        if text.count("\nproxy ") and not _active(config.http):
            raise ValueError("HTTP-прокси слушает без пользователей")
    if "\x00" in text or "$(" in text or "`" in text:
        raise ValueError("конфигурация 3proxy содержит запрещённую последовательность")


def _idle_config() -> str:
    return "\n".join(["nserver 1.1.1.1", "nscache 65536", "log", "auth strong", "deny * * *", ""])


def _active(listener: Listener) -> bool:
    return listener.enabled and bool(listener.users)


def _acl(listener: Listener, kind: str, secrets: dict[str, str]) -> list[str]:
    return [
        "auth strong",
        "users " + " ".join(_user_rows(listener, kind, secrets)),
        *_deny_lines(),
        _allow(listener),
    ]


def _user_rows(listener: Listener, kind: str, secrets: dict[str, str]) -> list[str]:
    rows: list[str] = []
    for user in listener.users:
        username = validate_username(user.username)
        expected = f"{kind}:{username}"
        if user.secret_ref != expected:
            raise ValueError(f"некорректная ссылка на секрет для {username}")
        password = validate_password(secrets.get(user.secret_ref, ""))
        rows.append(f"{username}:CL:{password}")
    if not rows:
        raise ValueError("нельзя включить прокси без пользователей")
    return rows


def _allow(listener: Listener) -> str:
    names = ",".join(validate_username(user.username) for user in listener.users)
    if listener.allowlist:
        return f"allow {names} {','.join(listener.allowlist)}"
    return f"allow {names}"


def _deny_lines() -> list[str]:
    lines = [f"deny * * {network}" for network in BLOCKED_NETS]
    lines.extend(f"deny * * {host}" for host in BLOCKED_HOST_DENIES)
    lines.append("deny * * 169.254.169.254")
    return lines
