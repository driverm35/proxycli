"""Read-only view of the 3proxy ACL and its log. Never returns passwords."""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime

ERROR_CODES = {
    0: "успех",
    1: "запрещено правилом deny (цель в закрытой сети)",
    3: "нет подходящего allow: адрес клиента не в allowlist",
    4: "клиент не прислал логин (анонимный SOCKS5)",
    5: "такого пользователя нет в конфиге 3proxy",
    6: "неверный пароль",
    13: "3proxy не смог подключиться к цели",
    92: "соединение закрыто по таймауту",
    100: "имя цели не разрешилось (DNS)",
}

_LOG_LINE = re.compile(
    r"^(?P<ts>\d{12})\.\d{3} (?P<port>\d+) (?P<code>\d{5}) (?P<user>\S+) "
    r"(?P<client>\[?[0-9A-Fa-f:.]+\]?):\d+ (?P<target>\S+)"
)


@dataclass(frozen=True)
class LogEntry:
    when: str
    port: int
    code: int
    user: str
    client: str
    target: str


def acl_lines(cfg_text: str) -> list[str]:
    """ACL lines of a rendered 3proxy.cfg with the users line reduced to names."""
    shown: list[str] = []
    denies = 0
    for line in cfg_text.splitlines():
        if line.startswith("users "):
            names = [row.split(":", 1)[0] for row in line.split()[1:]]
            shown.append("users " + " ".join(names) + " (пароли скрыты)")
        elif line.startswith("deny * * "):
            denies += 1
        elif line.startswith(("auth ", "allow ", "deny ", "socks ", "proxy ", "flush")):
            if denies:
                shown.append(f"deny * * <закрытые сети и metadata>: {denies} правил")
                denies = 0
            shown.append(line)
    return shown


def parse_log(text: str, port: int) -> list[LogEntry]:
    entries: list[LogEntry] = []
    for line in text.splitlines():
        match = _LOG_LINE.match(line.strip())
        if not match or int(match["port"]) != port:
            continue
        client = match["client"].strip("[]")
        if client == "0.0.0.0":
            continue
        entries.append(
            LogEntry(
                when=_when(match["ts"]),
                port=port,
                code=int(match["code"]),
                user=match["user"],
                client=client,
                target=match["target"],
            )
        )
    return entries


def summarize(entries: list[LogEntry], limit: int = 10) -> list[str]:
    counts: Counter[tuple[str, int, str]] = Counter()
    last: dict[tuple[str, int, str], str] = {}
    for entry in entries:
        key = (entry.client, entry.code, entry.user)
        counts[key] += 1
        last[key] = entry.when
    rows: list[str] = []
    for key in sorted(counts, key=lambda item: last[item], reverse=True)[:limit]:
        client, code, user = key
        rows.append(
            f"{client} user={user} код {code} ({describe(code)}): "
            f"{counts[key]} раз, последний {last[key]} UTC"
        )
    return rows


def describe(code: int) -> str:
    return ERROR_CODES.get(code, "см. коды ошибок 3proxy")


def allowed_by(allowlist: list[str], address: str) -> bool | None:
    """True/False if address matches the allowlist; None for an empty list (any source)."""
    if not allowlist:
        return None
    ip = ipaddress.ip_address(address)
    return any(ip in ipaddress.ip_network(item, strict=False) for item in allowlist)


def _when(stamp: str) -> str:
    try:
        parsed = datetime.strptime(stamp, "%y%m%d%H%M%S")
    except ValueError:
        return stamp
    return parsed.strftime("%Y-%m-%d %H:%M:%S")
