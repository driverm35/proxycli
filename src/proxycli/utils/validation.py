from __future__ import annotations

import ipaddress
import re
from urllib.parse import unquote, urlsplit

from proxycli.constants import DEFAULT_HTTP_PORT, DEFAULT_SOCKS_PORT, SSH_PORT
from proxycli.errors import ValidationError
from proxycli.utils.net import (
    is_blocked_host,
    is_blocked_ip,
    is_forbidden_upstream_host,
    is_public_ipv4,
)

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_EMAIL = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$")
_USER = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}$")
_PASSWORD = re.compile(r"^[A-Za-z0-9]{12,128}$")
_TOKEN = re.compile(r"^[A-Za-z0-9_-]{20,256}$")
_FORBIDDEN = ("\x00", "\n", "\r", "`", "$(", "${", ";", "|", "&", "<", ">", "\\", "'", '"')
_UPSTREAM_PATH = re.compile(r"^/(?:[A-Za-z0-9._~-]+/)*[A-Za-z0-9._~-]+/?$")


def _reject_control(value: str, label: str) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{label}: ожидалась строка")
    stripped = value.strip()
    for token in _FORBIDDEN:
        if token in stripped:
            raise ValidationError(f"{label}: запрещённые символы")
    if any(ord(char) < 32 or ord(char) == 127 for char in stripped):
        raise ValidationError(f"{label}: запрещённые символы")
    return stripped


def validate_subdomain(value: str) -> str:
    name = _reject_control(value, "поддомен").lower()
    if not _LABEL.fullmatch(name):
        raise ValidationError(
            "поддомен должен быть одной DNS-меткой (a-z, 0-9, дефис)",
            fix="пример: pay",
        )
    return name


def validate_domain(value: str) -> str:
    raw = _reject_control(value, "домен").lower()
    if raw.startswith("*."):
        raw = raw[2:]
    labels = raw.split(".")
    if len(labels) < 2 or any(not _LABEL.fullmatch(label) for label in labels):
        raise ValidationError(
            "домен должен быть вида hooks.example.com, без схемы и пути",
            fix="пример: hooks.example.com",
        )
    if len(raw) > 253:
        raise ValidationError("домен слишком длинный")
    return raw


def validate_email(value: str) -> str:
    email = _reject_control(value, "email")
    if not _EMAIL.fullmatch(email) or len(email) > 254:
        raise ValidationError("некорректный email для ACME", fix="пример: admin@example.com")
    return email


def validate_username(value: str) -> str:
    name = _reject_control(value, "имя пользователя")
    if not _USER.fullmatch(name):
        raise ValidationError(
            "имя пользователя: латиница, далее латиница, цифры, _ или -; до 32 символов"
        )
    return name


def validate_password(value: str) -> str:
    if not isinstance(value, str) or not _PASSWORD.fullmatch(value):
        raise ValidationError("пароль: 12–128 символов, только латиница и цифры")
    return value


def validate_token(value: str) -> str:
    token = value.strip() if isinstance(value, str) else ""
    if not _TOKEN.fullmatch(token):
        raise ValidationError("токен Cloudflare: 20–256 символов A-Z, a-z, 0-9, _ и -")
    return token


def validate_public_ipv4(value: str) -> str:
    ip = _reject_control(value, "IPv4")
    if not is_public_ipv4(ip):
        raise ValidationError(
            "нужен публичный глобальный IPv4",
            fix="узнайте адрес у провайдера VPS или: curl -4 https://api.ipify.org",
        )
    return ip


def validate_port(value: int, *, kind: str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"порт {kind} должен быть числом") from exc
    if port < 1 or port > 65535:
        raise ValidationError(f"порт {kind} вне диапазона 1–65535")
    reserved = {SSH_PORT, 80, 443}
    if kind in {"socks", "http"} and port in reserved:
        raise ValidationError(
            f"порт {port} занят SSH или Caddy и не используется для прокси",
            fix=f"оставьте {DEFAULT_SOCKS_PORT if kind == 'socks' else DEFAULT_HTTP_PORT}",
        )
    return port


def validate_allowlist(entries: list[str]) -> list[str]:
    cleaned: list[str] = []
    for raw in entries:
        item = _reject_control(raw, "allowlist")
        if item in {"0.0.0.0/0", "::/0", "*"}:
            raise ValidationError("широкий allowlist не нужен: оставьте список пустым")
        try:
            if "/" in item:
                network = ipaddress.ip_network(item, strict=False)
                cleaned.append(str(network))
            else:
                cleaned.append(str(ipaddress.ip_address(item)))
        except ValueError as exc:
            raise ValidationError(f"некорректный IP или CIDR: {item}") from exc
    return cleaned


def validate_upstream(value: str) -> str:
    if not isinstance(value, str):
        raise ValidationError("upstream: ожидалась строка")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValidationError("upstream: запрещённые символы")
    raw = _reject_control(value, "upstream")
    decoded = unquote(raw)
    if decoded != raw:
        _reject_control(decoded, "upstream")
    parts = urlsplit(raw)
    if parts.scheme not in {"http", "https"}:
        raise ValidationError("upstream должен начинаться с http:// или https://")
    if parts.username is not None or parts.password is not None:
        raise ValidationError("upstream не должен содержать логин или пароль")
    if parts.query or parts.fragment:
        raise ValidationError("upstream — без query и fragment; query входящего запроса сохраняется")
    path = _validate_upstream_path(parts.path)
    host = parts.hostname
    if not host:
        raise ValidationError("у upstream нет хоста")
    host = _validate_upstream_host(host.lower())
    try:
        port = parts.port
    except ValueError as exc:
        raise ValidationError("некорректный порт upstream") from exc
    if port == SSH_PORT:
        raise ValidationError("upstream не может указывать на порт SSH")
    default = 443 if parts.scheme == "https" else 80
    port_part = "" if port in {None, default} else f":{port}"
    if ":" in host:
        origin = f"{parts.scheme}://[{host}]{port_part}"
    else:
        origin = f"{parts.scheme}://{host}{port_part}"
    if path:
        return f"{origin}{path}"
    return origin


def _validate_upstream_path(path: str) -> str:
    if path in {"", "/"}:
        return ""
    if len(path) > 512 or not path.startswith("/") or not _UPSTREAM_PATH.fullmatch(path):
        raise ValidationError(
            "путь upstream содержит недопустимые символы",
            fix="пример: https://api.example.com/admin/telegram/webhook/",
        )
    segments = [segment for segment in path.split("/") if segment]
    if any(segment in {".", ".."} for segment in segments):
        raise ValidationError("некорректный путь upstream")
    return path


def _validate_upstream_host(host: str) -> str:
    if not host or len(host) > 253 or host.startswith("*") or ".." in host or any(char.isspace() for char in host):
        raise ValidationError("некорректный хост upstream")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = host.split(".")
    if not labels or any(not _LABEL.fullmatch(label) for label in labels):
        raise ValidationError(
            "некорректный хост upstream",
            fix="пример: api.example.com или 10.0.0.5",
        )
    return host


def upstream_host_port(origin: str) -> tuple[str, int, str]:
    parts = urlsplit(origin)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return host, port, parts.scheme


def upstream_base_path(origin: str) -> str:
    path = urlsplit(origin).path
    if path in {"", "/"}:
        return ""
    return path


def upstream_rewrite_prefix(base_path: str) -> str | None:
    """Base path without a trailing slash. None means the incoming URI is kept."""
    if base_path in {"", "/"}:
        return None
    return base_path.rstrip("/")


def join_upstream_path(base_path: str, incoming_uri: str) -> str:
    """Append an incoming path and query to an upstream base path.

    An incoming ``/`` keeps exactly one trailing slash. ``/extra?x=1`` becomes
    ``<base>/extra?x=1`` with one slash at the join. An empty base returns the
    incoming URI unchanged.
    """
    if base_path in {"", "/"}:
        return incoming_uri
    prefix = base_path.rstrip("/")
    path, separator, query = incoming_uri.partition("?")
    if not path.startswith("/"):
        path = "/" + path
    joined = prefix + path
    if separator:
        return f"{joined}?{query}"
    return joined


def upstream_is_private_literal(origin: str) -> bool:
    host, _port, _scheme = upstream_host_port(origin)
    return is_blocked_host(host) or is_blocked_ip(host)


def upstream_is_forbidden(origin: str) -> bool:
    host, _port, _scheme = upstream_host_port(origin)
    return is_forbidden_upstream_host(host)


def upstream_requires_trust(origin: str) -> bool:
    """Private hosts may be confirmed. Loopback, link-local, and metadata may not."""
    if upstream_is_forbidden(origin):
        return False
    return upstream_is_private_literal(origin)


def secret_ref(kind: str, username: str) -> str:
    if kind not in {"socks", "http"}:
        raise ValidationError("неизвестный тип секрета")
    return f"{kind}:{validate_username(username)}"
