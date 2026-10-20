"""Terminal output helpers. Status words do not depend on color."""

from __future__ import annotations

import os
import sys

from rich.console import Console

from proxycli.models.config import AppConfig, Listener

CLEARTEXT_WARNING = (
    "Пароль HTTP-прокси передаётся в открытом виде между клиентом и прокси. "
    "Для доступа из интернета нужен отдельный защищённый канал."
)

DNS_HELP = (
    "Создайте DNS A-запись *.домен на публичный IPv4 этого сервера. "
    "Это только запись DNS. Она не выпускает wildcard-сертификат."
)


def plain_terminal() -> bool:
    return os.environ.get("TERM") == "dumb" or "NO_COLOR" in os.environ


def console() -> Console:
    return Console(
        no_color=plain_terminal(),
        force_terminal=False,
        emoji=False,
        highlight=False,
        soft_wrap=True,
        safe_box=plain_terminal() or not _utf8(),
    )


def curl_example(host: str, port: int, username: str) -> str:
    return f"curl -x http://{username}:****@{host}:{port} https://example.com"


def socks_example(host: str, port: int, username: str) -> str:
    return f"socks5://{username}:****@{host}:{port}"


def format_user_list(kind: str, config: AppConfig) -> str:
    """Readable proxy users. The stored password is never included."""
    listener = _listener(kind, config)
    title = "Пользователи SOCKS5:" if kind == "socks" else "Пользователи HTTP-прокси:"
    if not listener.users:
        return f"{title}\nПользователей нет."
    state = "включён" if listener.enabled else "заблокирован"
    lines = [title]
    for user in listener.users:
        parts = [
            user.username,
            f"порт {listener.port}",
            f"состояние: {state}",
            "пароль: ****",
        ]
        if listener.allowlist:
            parts.append("allowlist: " + ", ".join(listener.allowlist))
        lines.append("  ".join(parts))
    return "\n".join(lines)


def reveal_user(
    kind: str,
    username: str,
    config: AppConfig,
    secrets: dict[str, str] | None,
) -> str:
    """Password plus connection line. None means the secrets file is missing."""
    listener = _listener(kind, config)
    user = listener.user(username)
    if user is None:
        return "Пользователь не найден."
    if secrets is None:
        return "Файл секретов отсутствует, пароль показать нельзя."
    if not secrets:
        return "Файл секретов пуст, пароль не сохранён."
    secret = secrets.get(user.secret_ref, "")
    if not secret:
        return "Пароль для этого пользователя не найден."
    host = config.public_ipv4 or "SERVER_IP"
    if kind == "http":
        connection = f"curl -x http://{user.username}:{secret}@{host}:{listener.port} https://example.com"
    else:
        connection = f"socks5://{user.username}:{secret}@{host}:{listener.port}"
    return "\n".join(
        [
            f"Пароль: {secret}",
            f"Пользователь: {user.username}",
            f"Хост: {host}",
            f"Порт: {listener.port}",
            f"Подключение: {connection}",
            "Скопируйте пароль или строку подключения.",
        ]
    )


def _listener(kind: str, config: AppConfig) -> Listener:
    if kind == "socks":
        return config.socks
    if kind == "http":
        return config.http
    raise ValueError(f"неизвестный тип прокси: {kind}")


def route_added_text(public_host: str, upstream: str) -> str:
    public = f"https://{public_host}"
    return "\n".join(
        [
            f"{public} принимает запрос и отправляет его на {upstream}.",
            f"Укажите в Telegram (Bot API setWebhook) адрес {public}",
            "Если в публичном адресе будет путь, он добавится к базовому пути апстрима. "
            "Для Telegram укажите только хост, без пути.",
        ]
    )


def copy_secret(secret: str) -> bool:
    if not sys.stdout.isatty() or plain_terminal():
        return False
    import base64

    payload = base64.b64encode(secret.encode("utf-8")).decode("ascii")
    try:
        sys.stdout.write(f"\033]52;c;{payload}\a")
        sys.stdout.flush()
    except OSError:
        return False
    return True


def _utf8() -> bool:
    encoding = (sys.stdout.encoding or "").lower().replace("-", "")
    return encoding in {"utf8", "utf-8"}
