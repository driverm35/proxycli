from __future__ import annotations

from proxycli.models.config import AppConfig, Route
from proxycli.utils.validation import (
    upstream_host_port,
    validate_domain,
    validate_subdomain,
    validate_upstream,
)

WILDCARD_FALLBACK = (
    "Режим B (wildcard DNS-01) не активен: модуль dns.providers.cloudflare не подтверждён. "
    "Wildcard-сертификат НЕ выпущен и успех wildcard TLS не заявляется. "
    "Сгенерирован режим A: отдельный сертификат на каждый хост через HTTP-01/TLS-ALPN-01, "
    "когда A-запись этого хоста указывает на сервер."
)


def effective_dns(config: AppConfig) -> bool:
    return config.tls.mode == "dns" and config.tls.dns_plugin_ready


def render_caddyfile(config: AppConfig) -> tuple[str, list[str]]:
    warnings: list[str] = []
    if config.tls.mode == "dns" and not config.tls.dns_plugin_ready:
        warnings.append(WILDCARD_FALLBACK)
    lines: list[str] = ["{"]
    if config.tls.acme_email:
        lines.append(f"\temail {config.tls.acme_email}")
    lines.append("\tadmin off")
    lines.append("}")
    lines.append("")
    enabled = [route for route in config.routes if route.enabled]
    if not enabled:
        lines.extend(
            [
                ":80 {",
                "\trespond /health \"ok\" 200",
                "\trespond \"proxycli\" 404",
                "}",
            ]
        )
        return _finish(lines), warnings
    domain = validate_domain(config.wildcard_domain) if config.wildcard_domain else ""
    if not domain:
        raise ValueError("для маршрутов нужен wildcard-домен")
    if effective_dns(config):
        lines.extend(_wildcard_site(config, domain, enabled))
    else:
        for route in enabled:
            lines.extend(_host_site(route, domain))
            lines.append("")
    return _finish(lines), warnings


def _host_site(route: Route, domain: str) -> list[str]:
    host = f"{validate_subdomain(route.subdomain)}.{domain}"
    return [f"{host} {{", *_proxy_lines(route, "\t"), "}"]


def _wildcard_site(config: AppConfig, domain: str, routes: list[Route]) -> list[str]:
    lines = [f"*.{domain}, {domain} {{", "\ttls {", "\t\tdns cloudflare {env.CLOUDFLARE_API_TOKEN}", "\t}"]
    for route in routes:
        sub = validate_subdomain(route.subdomain)
        host = f"{sub}.{domain}"
        matcher = _matcher(sub)
        lines.append(f"\t@{matcher} host {host}")
        lines.append(f"\thandle @{matcher} {{")
        lines.extend(_proxy_lines(route, "\t\t"))
        lines.append("\t}")
    lines.extend(["\thandle {", "\t\trespond \"not found\" 404", "\t}", "}"])
    return lines


def _proxy_lines(route: Route, indent: str) -> list[str]:
    origin = validate_upstream(route.upstream)
    host, port, scheme = upstream_host_port(origin)
    if ":" in host:
        target = f"{scheme}://[{host}]:{port}"
    else:
        target = f"{scheme}://{host}:{port}"
    inner = indent + "\t"
    return [
        f"{indent}reverse_proxy {target} {{",
        f"{inner}header_up Host {{upstream_hostport}}",
        f"{inner}header_up X-Real-IP {{remote_host}}",
        f"{inner}header_up X-Forwarded-For {{remote_host}}",
        f"{inner}header_up X-Forwarded-Proto {{scheme}}",
        f"{inner}header_up X-Forwarded-Host {{host}}",
        f"{indent}}}",
    ]


def _matcher(subdomain: str) -> str:
    return "h_" + subdomain.replace("-", "_")


def _finish(lines: list[str]) -> str:
    text = "\n".join(lines).rstrip() + "\n"
    if "$(" in text or "`" in text or "\x00" in text:
        raise ValueError("Caddyfile содержит запрещённую последовательность")
    _balanced(text)
    return text


def _balanced(text: str) -> None:
    depth = 0
    for char in text:
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        if depth < 0:
            raise ValueError("Caddyfile: лишняя закрывающая скобка")
    if depth != 0:
        raise ValueError("Caddyfile: скобки не сбалансированы")


def assert_caddyfile_contains_routes(text: str, config: AppConfig) -> None:
    for route in config.routes:
        if not route.enabled:
            continue
        host = f"{route.subdomain}.{config.wildcard_domain}"
        if host not in text:
            raise ValueError(f"в Caddyfile нет {host}")
        if "X-Forwarded-For" not in text or "X-Forwarded-Host" not in text:
            raise ValueError("в Caddyfile нет заголовков X-Forwarded-*")
        if "tls_insecure_skip_verify" in text:
            raise ValueError("пропуск проверки TLS запрещён")
