"""Terminal output helpers. Status words do not depend on color."""

from __future__ import annotations

import os
import sys

from rich.console import Console

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
