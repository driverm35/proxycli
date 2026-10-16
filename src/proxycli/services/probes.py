from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass, field
from urllib.error import URLError
from urllib.request import Request, urlopen

from proxycli.errors import ProbeError
from proxycli.utils.net import is_blocked_host, is_blocked_ip, is_public_ipv4
from proxycli.utils.timeouts import call_with_timeout
from proxycli.utils.validation import upstream_host_port

ALIVE_HTTP = frozenset({401, 403, 404})


@dataclass
class LayerResult:
    layer: str
    status: str
    detail: str
    fix: str = ""


@dataclass
class ProbeReport:
    layers: list[LayerResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        required = [item for item in self.layers if item.status != "skip"]
        return bool(required) and all(item.status == "ok" for item in required)

    def failed(self) -> LayerResult | None:
        for item in self.layers:
            if item.status == "fail":
                return item
        return None

    def summary(self) -> str:
        failed = self.failed()
        if failed:
            return f"{failed.layer}: {failed.detail}"
        return "; ".join(f"{item.layer}={item.status}" for item in self.layers)


def resolve_ipv4(host: str, timeout: float) -> list[str]:
    def _do() -> list[str]:
        socket.setdefaulttimeout(timeout)
        try:
            infos = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
        finally:
            socket.setdefaulttimeout(None)
        return sorted({item[4][0] for item in infos})

    try:
        return call_with_timeout(_do, timeout)
    except TimeoutError as exc:
        raise ProbeError(str(exc), layer="dns", fix=f"dig +time=3 A {host}") from exc
    except socket.gaierror as exc:
        raise ProbeError(f"DNS не резолвит {host}: {exc.strerror}", layer="dns", fix=f"dig A {host}") from exc


def tcp_open(host: str, port: int, timeout: float) -> None:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return
    except TimeoutError as exc:
        raise ProbeError(f"TCP {host}:{port} таймаут", layer="tcp", fix=f"nc -vz {host} {port}") from exc
    except OSError as exc:
        raise ProbeError(
            f"TCP {host}:{port}: {exc.strerror or exc}",
            layer="tcp",
            fix=f"nc -vz {host} {port}",
        ) from exc


def tls_probe(host: str, port: int, timeout: float, server_name: str) -> None:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=server_name) as secure:
                cert = secure.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        raise ProbeError(
            f"TLS сертификат не принят для {server_name}: {exc.verify_message}",
            layer="tls",
            fix="сертификат ещё не выпущен или имя не совпадает; успех TLS не заявляется",
        ) from exc
    except (ssl.SSLError, OSError, TimeoutError) as exc:
        raise ProbeError(
            f"TLS {server_name}: {exc}",
            layer="tls",
            fix="openssl s_client -connect host:443 -servername host",
        ) from exc
    if not cert:
        raise ProbeError("TLS рукопожатие без проверенного сертификата", layer="tls")
    names = _cert_names(cert)
    wildcard = f"*.{server_name.split('.', 1)[-1]}"
    if server_name not in names and wildcard not in names:
        raise ProbeError(
            f"сертификат не покрывает {server_name}",
            layer="tls",
            fix="не заявляйте wildcard TLS, пока имя не появится в сертификате",
        )


def http_status(host: str, port: int, scheme: str, timeout: float, server_name: str | None = None) -> int:
    name = server_name or host
    try:
        status = _exchange(host, port, scheme, timeout, name, "HEAD")
        if status == 405:
            status = _exchange(host, port, scheme, timeout, name, "GET")
        return status
    except (OSError, TimeoutError, ssl.SSLError, ProbeError) as exc:
        if isinstance(exc, ProbeError):
            raise
        raise ProbeError(f"HTTP {scheme}://{name}:{port}: {exc}", layer="http", fix="curl -I --max-time 5 URL") from exc


def probe_upstream(origin: str, timeout: float, *, trust_private: bool) -> ProbeReport:
    host, port, scheme = upstream_host_port(origin)
    report = ProbeReport()
    addresses = _addresses(host, timeout, report)
    if report.failed():
        return report
    if any(is_blocked_ip(ip) or is_blocked_host(host) for ip in addresses) and not trust_private:
        report.layers.append(
            LayerResult(
                "policy",
                "fail",
                "upstream в частной или служебной сети",
                "повторите с явным --trust-private, если это ваш сервер",
            )
        )
        return report
    target = addresses[0]
    try:
        tcp_open(target, port, timeout)
        report.layers.append(LayerResult("tcp", "ok", f"{target}:{port}"))
    except ProbeError as exc:
        report.layers.append(LayerResult(exc.layer, "fail", exc.message, exc.fix))
        return report
    if scheme == "https":
        try:
            tls_probe(target, port, timeout, host)
            report.layers.append(LayerResult("tls", "ok", host))
        except ProbeError as exc:
            report.layers.append(LayerResult("tls", "fail", exc.message, exc.fix))
            return report
    else:
        report.layers.append(LayerResult("tls", "skip", "upstream без TLS"))
    try:
        status = http_status(target, port, scheme, timeout, host)
    except ProbeError as exc:
        report.layers.append(LayerResult("http", "fail", exc.message, exc.fix))
        return report
    detail = f"HTTP {status}"
    if status in ALIVE_HTTP:
        detail += " (ответ есть, маршрут не считается мёртвым)"
    report.layers.append(LayerResult("http", "ok", detail))
    return report


def probe_public_https(hostname: str, expected_ip: str, timeout: float) -> ProbeReport:
    report = ProbeReport()
    try:
        addresses = resolve_ipv4(hostname, timeout)
    except ProbeError as exc:
        report.layers.append(LayerResult("dns", "fail", exc.message, exc.fix))
        return report
    if expected_ip and expected_ip not in addresses:
        report.layers.append(
            LayerResult(
                "dns",
                "fail",
                f"{hostname} -> {', '.join(addresses)}; ожидался {expected_ip}",
                f"создайте A-запись {hostname} на {expected_ip}",
            )
        )
        return report
    report.layers.append(LayerResult("dns", "ok", ", ".join(addresses)))
    target = expected_ip or addresses[0]
    try:
        tcp_open(target, 443, timeout)
        report.layers.append(LayerResult("tcp", "ok", f"{target}:443"))
        tls_probe(target, 443, timeout, hostname)
        report.layers.append(LayerResult("tls", "ok", f"сертификат принят для {hostname}"))
        status = http_status(target, 443, "https", timeout, hostname)
        note = f"HTTP {status}"
        if status in ALIVE_HTTP:
            note += " (не мёртвый маршрут)"
        report.layers.append(LayerResult("http", "ok", note))
    except ProbeError as exc:
        report.layers.append(LayerResult(exc.layer, "fail", exc.message, exc.fix))
    return report


def dns_not_saved_message(domain: str, public_ip: str, detail: str) -> str:
    return (
        "Проверка DNS не совпала. Домен не сохранён, Caddy не запускался и не изменялся. "
        f"{detail} "
        f"Создайте A-запись *.{domain} или proxycli-check.{domain} на {public_ip}. "
        "После этого снова запустите sudo proxycli."
    )


def check_name_dns(domain: str, public_ip: str, timeout: float) -> tuple[bool, str]:
    name = f"proxycli-check.{domain}"
    try:
        addresses = resolve_ipv4(name, timeout)
    except ProbeError as exc:
        return False, (
            f"{exc.message}. Создайте A-запись *.{domain} или {name} на {public_ip}. "
            "Пока проверка не совпала, wildcard DNS не подтверждён."
        )
    if public_ip not in addresses:
        return False, f"{name} -> {', '.join(addresses)}, а не {public_ip}. Wildcard DNS не подтверждён."
    return True, f"{name} указывает на {public_ip}"


def detect_public_ipv4(timeout: float = 5) -> str | None:
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
        try:
            text = _fetch_text(url, timeout).strip()
        except (OSError, URLError, TimeoutError, ValueError):
            continue
        if is_public_ipv4(text):
            return text
    return None


def socks5_noauth_rejected(host: str, port: int, timeout: float) -> bool:
    reply = _socks_greeting(host, port, b"\x05\x01\x00", timeout)
    if reply[0] != 5:
        raise ProbeError("порт не ответил как SOCKS5", layer="socks", fix=f"ss -ltnp | grep {port}")
    return reply[1] != 0x00


def socks5_connect(
    proxy_host: str,
    proxy_port: int,
    username: str,
    password: str,
    dest_host: str,
    dest_port: int,
    timeout: float,
) -> int:
    with socket.create_connection((proxy_host, proxy_port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x02")
        method = _readexact(sock, 2)
        if method != b"\x05\x02":
            raise ProbeError(f"SOCKS5 не выбрал пароль: {method.hex()}", layer="socks")
        user = username.encode("utf-8")
        passwd = password.encode("utf-8")
        sock.sendall(bytes([1, len(user)]) + user + bytes([len(passwd)]) + passwd)
        auth = _readexact(sock, 2)
        if auth[1] != 0:
            raise ProbeError("SOCKS5 отклонил логин или пароль", layer="socks")
        host = dest_host.encode("utf-8")
        packet = b"\x05\x01\x00\x03" + bytes([len(host)]) + host + dest_port.to_bytes(2, "big")
        sock.sendall(packet)
        head = _readexact(sock, 4)
        if head[1] != 0:
            return int(head[1])
        _drain_socks_addr(sock, head[3])
        return 0


def http_proxy_status(
    proxy_host: str,
    proxy_port: int,
    dest_host: str,
    dest_port: int,
    timeout: float,
    username: str | None = None,
    password: str | None = None,
) -> int:
    import base64

    with socket.create_connection((proxy_host, proxy_port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        lines = [f"CONNECT {dest_host}:{dest_port} HTTP/1.1", f"Host: {dest_host}:{dest_port}"]
        if username is not None and password is not None:
            token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
            lines.append(f"Proxy-Authorization: Basic {token}")
        sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
        data = b""
        while b"\r\n" not in data:
            chunk = sock.recv(256)
            if not chunk:
                break
            data += chunk
            if len(data) > 4096:
                break
    parts = data.decode("iso-8859-1", errors="replace").split()
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        raise ProbeError("прокси не вернул HTTP-ответ", layer="http")
    return int(parts[1])


def _addresses(host: str, timeout: float, report: ProbeReport) -> list[str]:
    if is_blocked_ip(host) or _is_ip(host):
        report.layers.append(LayerResult("dns", "skip", "литерал IP"))
        return [host]
    try:
        found = resolve_ipv4(host, timeout)
    except ProbeError as exc:
        report.layers.append(LayerResult("dns", "fail", exc.message, exc.fix))
        return []
    report.layers.append(LayerResult("dns", "ok", ", ".join(found)))
    return found


def _is_ip(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET, host)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except OSError:
        return False


def _exchange(host: str, port: int, scheme: str, timeout: float, server_name: str, method: str) -> int:
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        channel: socket.socket | ssl.SSLSocket
        if scheme == "https":
            context = ssl.create_default_context()
            channel = context.wrap_socket(raw, server_hostname=server_name)
        else:
            channel = raw
        channel.settimeout(timeout)
        request = (
            f"{method} / HTTP/1.1\r\nHost: {server_name}\r\n"
            "Connection: close\r\nUser-Agent: proxycli-probe\r\n\r\n"
        )
        channel.sendall(request.encode("ascii"))
        data = b""
        while b"\r\n" not in data:
            chunk = channel.recv(256)
            if not chunk:
                break
            data += chunk
            if len(data) > 8192:
                break
    finally:
        raw.close()
    parts = data.decode("iso-8859-1", errors="replace").split()
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        raise ProbeError("нет HTTP-ответа", layer="http")
    return int(parts[1])


def _fetch_text(url: str, timeout: float) -> str:
    request = Request(url, method="GET", headers={"User-Agent": "proxycli"})
    with urlopen(request, timeout=timeout) as response:
        return response.read(128).decode("ascii", errors="replace")


def _cert_names(cert: dict[str, object]) -> set[str]:
    names: set[str] = set()
    for key, value in cert.get("subjectAltName", ()):
        if key == "DNS":
            names.add(str(value).lower())
    return names


def _socks_greeting(host: str, port: int, payload: bytes, timeout: float) -> bytes:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(payload)
            return _readexact(sock, 2)
    except OSError as exc:
        raise ProbeError(f"SOCKS5 {host}:{port}: {exc}", layer="socks", fix=f"ss -ltnp | grep {port}") from exc


def _readexact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ProbeError("сокет закрылся раньше ответа", layer="socks")
        data += chunk
    return data


def _drain_socks_addr(sock: socket.socket, atyp: int) -> None:
    if atyp == 1:
        _readexact(sock, 6)
    elif atyp == 3:
        length = _readexact(sock, 1)[0]
        _readexact(sock, length + 2)
    elif atyp == 4:
        _readexact(sock, 18)
