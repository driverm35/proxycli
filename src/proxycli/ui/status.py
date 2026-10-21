"""Plain status text for menus and non-interactive output."""

from __future__ import annotations

import os
import sys

from proxycli import __version__
from proxycli.constants import CADDY_CONTAINER, PROXY_CONTAINER


def unicode_disabled() -> bool:
    return "NO_COLOR" in os.environ or os.environ.get("TERM") == "dumb"


def interactive() -> bool:
    if unicode_disabled():
        return False
    return sys.stdin.isatty() and sys.stdout.isatty()


def plain_status(stack: object) -> str:
    config = stack.store.load()
    caddy = stack.container_state(CADDY_CONTAINER)
    proxy = stack.container_state(PROXY_CONTAINER)
    domain = config.wildcard_domain or "не задан"
    tls = config.tls.mode
    ready = "да" if config.tls.dns_plugin_ready else "нет"
    return "\n".join(
        [
            f"ProxyCLI {__version__}",
            f"Caddy: {caddy}",
            f"3proxy: {proxy}",
            f"Домен: {domain}",
            f"TLS: {tls}, DNS-плагин готов: {ready}",
            f"Маршрутов: {len(config.routes)}",
            f"SOCKS5: порт {config.socks.port}, пользователей: {len(config.socks.users)}",
            f"HTTP пользователей: {len(config.http.users)}",
        ]
    )
