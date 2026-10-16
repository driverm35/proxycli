from __future__ import annotations

import json
from typing import Any

from proxycli.constants import SSH_PORT
from proxycli.errors import ValidationError
from proxycli.models.config import AppConfig
from proxycli.services.proxy3cfg import _active

PortSpec = tuple[str, int]


def parse_ruleset(raw: str) -> dict[str, Any]:
    if not raw.strip():
        return {"nftables": []}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValidationError("nftables вернул не-JSON", fix="nft -j list ruleset") from exc
    if not isinstance(data, dict):
        raise ValidationError("неожиданный ответ nftables")
    return data


def managed_ports(config: AppConfig) -> list[PortSpec]:
    ports: list[PortSpec] = [("tcp", 80), ("tcp", 443), ("udp", 443)]
    if _active(config.socks):
        ports.append(("tcp", config.socks.port))
    if _active(config.http):
        ports.append(("tcp", config.http.port))
    for _proto, port in ports:
        if port == SSH_PORT:
            raise ValidationError("ProxyCLI не управляет портом SSH")
    return ports


def plan_apply(ruleset: dict[str, Any], ports: list[PortSpec]) -> tuple[list[list[str]], str]:
    chains = _drop_input_chains(ruleset)
    if not chains:
        return [], (
            "Цепочка input с policy drop не найдена. "
            "Правила не добавлены: чужой firewall не изменялся и не сбрасывался."
        )
    family, table, chain = _prefer(chains)
    existing = _comments(ruleset)
    commands: list[list[str]] = []
    for proto, port in ports:
        if port == SSH_PORT:
            raise ValidationError("отказ добавлять правило для порта SSH")
        if proto not in {"tcp", "udp"}:
            raise ValidationError("поддерживаются только tcp и udp")
        comment = f"proxycli-{proto}-{port}"
        if comment in existing:
            continue
        commands.append(
            [
                "nft",
                "insert",
                "rule",
                family,
                table,
                chain,
                proto,
                "dport",
                str(port),
                "accept",
                "comment",
                comment,
            ]
        )
    note = "" if commands or existing else "правила proxycli уже совпадают с нужными портами"
    if not commands and existing:
        note = "правила proxycli уже есть, дубликаты не добавлялись"
    return commands, note


def plan_rollback(ruleset: dict[str, Any]) -> list[list[str]]:
    commands: list[list[str]] = []
    for item in ruleset.get("nftables", []):
        if not isinstance(item, dict):
            continue
        rule = item.get("rule")
        if not isinstance(rule, dict):
            continue
        comment = str(rule.get("comment", ""))
        if comment != "proxycli" and not comment.startswith("proxycli-"):
            continue
        handle = rule.get("handle")
        family = rule.get("family")
        table = rule.get("table")
        chain = rule.get("chain")
        if handle is None or not family or not table or not chain:
            continue
        commands.append(
            [
                "nft",
                "delete",
                "rule",
                str(family),
                str(table),
                str(chain),
                "handle",
                str(handle),
            ]
        )
    return commands


def command_is_unsafe(argv: list[str]) -> bool:
    if "flush" in argv or "ruleset" in argv:
        return True
    if "dport" not in argv:
        return False
    index = argv.index("dport")
    return index + 1 < len(argv) and argv[index + 1] == str(SSH_PORT)


def _drop_input_chains(ruleset: dict[str, Any]) -> list[tuple[str, str, str]]:
    found: list[tuple[str, str, str]] = []
    for item in ruleset.get("nftables", []):
        if not isinstance(item, dict):
            continue
        chain = item.get("chain")
        if not isinstance(chain, dict):
            continue
        if chain.get("hook") == "input" and chain.get("type") == "filter" and chain.get("policy") == "drop":
            found.append((str(chain["family"]), str(chain["table"]), str(chain["name"])))
    return found


def _prefer(chains: list[tuple[str, str, str]]) -> tuple[str, str, str]:
    for chain in chains:
        if chain[0] == "inet":
            return chain
    return chains[0]


def _comments(ruleset: dict[str, Any]) -> set[str]:
    found: set[str] = set()
    for item in ruleset.get("nftables", []):
        if not isinstance(item, dict):
            continue
        rule = item.get("rule")
        if isinstance(rule, dict) and rule.get("comment"):
            found.add(str(rule["comment"]))
    return found
