from __future__ import annotations

from pathlib import Path

from proxycli.constants import (
    CADDY_DNS_IMAGE,
    CADDY_DNS_PLUGIN,
    CADDY_IMAGE,
    CADDY_VERSION,
    COMPOSE_PROJECT,
    THREEPROXY_IMAGE,
)
from proxycli.models.config import AppConfig
from proxycli.services.proxy3cfg import _active

ENTRYPOINT = """#!/bin/sh
set -eu
if [ -f /run/secrets/cloudflare_token ]; then
  IFS= read -r CLOUDFLARE_API_TOKEN < /run/secrets/cloudflare_token || exit 1
  export CLOUDFLARE_API_TOKEN
fi
exec caddy "$@"
"""


def render_dockerfile() -> str:
    return (
        f"ARG CADDY_VERSION={CADDY_VERSION}\n"
        "FROM caddy:${CADDY_VERSION}-builder AS builder\n"
        "ARG CADDY_VERSION\n"
        f"ARG CF_PLUGIN={CADDY_DNS_PLUGIN}\n"
        'RUN xcaddy build "v${CADDY_VERSION}" --with "${CF_PLUGIN}"\n'
        "\n"
        "FROM caddy:${CADDY_VERSION}\n"
        "COPY entrypoint.sh /usr/local/bin/proxycli-entrypoint\n"
        "RUN chmod +x /usr/local/bin/proxycli-entrypoint\n"
        'ENTRYPOINT ["proxycli-entrypoint"]\n'
        'CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]\n'
    )


def render_compose(config: AppConfig, token_file: Path) -> str:
    use_dns = config.tls.mode == "dns" and config.tls.dns_plugin_ready
    image = CADDY_DNS_IMAGE if use_dns else CADDY_IMAGE
    lines = [
        f"name: {COMPOSE_PROJECT}",
        "services:",
        "  caddy:",
        f"    image: {image}",
        "    container_name: proxycli-caddy",
        "    restart: unless-stopped",
        "    ports:",
        '      - "80:80"',
        '      - "443:443"',
        '      - "443:443/udp"',
        "    volumes:",
        "      - ./caddy/Caddyfile:/etc/caddy/Caddyfile:ro",
        "      - caddy_data:/data",
        "      - caddy_config:/config",
        "    networks:",
        "      - proxycli",
        "    logging:",
        "      driver: json-file",
        "      options:",
        '        max-size: "10m"',
        '        max-file: "3"',
    ]
    if use_dns:
        quoted = _yaml_path(token_file)
        lines.extend(
            [
                "    secrets:",
                "      - cloudflare_token",
            ]
        )
    if _active(config.socks) or _active(config.http):
        lines.extend(_proxy_service(config))
    lines.extend(
        [
            "volumes:",
            "  caddy_data:",
            "  caddy_config:",
            "networks:",
            "  proxycli:",
            "    name: proxycli",
        ]
    )
    if use_dns:
        lines.extend(
            [
                "secrets:",
                "  cloudflare_token:",
                f"    file: {quoted}",
            ]
        )
    text = "\n".join(lines) + "\n"
    if "22:22" in text or '"22:' in text:
        raise ValueError("compose не должен публиковать SSH")
    return text


def _proxy_service(config: AppConfig) -> list[str]:
    lines = [
        "  proxy3:",
        f"    image: {THREEPROXY_IMAGE}",
        "    container_name: proxycli-3proxy",
        "    restart: unless-stopped",
        "    read_only: true",
        "    cap_drop:",
        "      - ALL",
        "    tmpfs:",
        "      - /tmp",
        "    ports:",
    ]
    if _active(config.socks):
        lines.append(f'      - "0.0.0.0:{config.socks.port}:{config.socks.port}"')
    if _active(config.http):
        lines.append(f'      - "0.0.0.0:{config.http.port}:{config.http.port}"')
    lines.extend(
        [
            "    volumes:",
            "      - ./3proxy/3proxy.cfg:/etc/3proxy/3proxy.cfg:ro",
            "    networks:",
            "      - proxycli",
            "    logging:",
            "      driver: json-file",
            "      options:",
            '        max-size: "10m"',
            '        max-file: "3"',
        ]
    )
    return lines


def _yaml_path(path: Path) -> str:
    text = path.as_posix()
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./:-")
    if not text or any(char not in allowed for char in text):
        raise ValueError("путь к токену нельзя безопасно записать в compose")
    return text
