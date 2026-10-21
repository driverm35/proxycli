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


def plan_replace_owned_port(
    ruleset: dict[str, Any],
    proto: str,
    old_port: int,
    new_port: int,
    *,
    delete_old: bool = True,
) -> list[list[str]]:
    """Replace one proxycli-owned port rule. Other comments are left untouched.

    The new accept rule is inserted before the old one is deleted. If this
    install never added a rule for the old port, nothing is planned.
    """
    if proto not in {"tcp", "udp"}:
        raise ValidationError("поддерживаются только tcp и udp")
    if old_port == SSH_PORT or new_port == SSH_PORT:
        raise ValidationError("ProxyCLI не управляет портом SSH")
    if new_port in {80, 443} or old_port in {80, 443}:
        raise ValidationError("правила Caddy для 80 и 443 этой командой не меняются")
    if old_port == new_port:
        return []
    comment_old = f"proxycli-{proto}-{old_port}"
    comment_new = f"proxycli-{proto}-{new_port}"
    owned = [rule for rule in _rule_dicts(ruleset) if str(rule.get("comment", "")) == comment_old]
    if not owned:
        return []
    family = str(owned[0].get("family") or "")
    table = str(owned[0].get("table") or "")
    chain = str(owned[0].get("chain") or "")
    if not family or not table or not chain:
        raise ValidationError(
            f"правило {comment_old} без family/table/chain, firewall не изменён",
            fix="nft -a list ruleset",
        )
    commands: list[list[str]] = []
    if comment_new not in _comments(ruleset):
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
                str(new_port),
                "accept",
                "comment",
                comment_new,
            ]
        )
    if delete_old:
        for rule in owned:
            handle = rule.get("handle")
            if handle is None:
                raise ValidationError(
                    f"правило {comment_old} без handle, удалять его нельзя",
                    fix="nft -a list ruleset",
                )
            commands.append(
                [
                    "nft",
                    "delete",
                    "rule",
                    str(rule.get("family") or family),
                    str(rule.get("table") or table),
                    str(rule.get("chain") or chain),
                    "handle",
                    str(handle),
                ]
            )
    for command in commands:
        if command_is_unsafe(command) or "flush" in command or "ruleset" in command:
            raise ValidationError("отказ: смена порта затронула бы SSH или сделала бы flush")
    return commands


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
    return {str(rule["comment"]) for rule in _rule_dicts(ruleset) if rule.get("comment")}


def _rule_dicts(ruleset: dict[str, Any]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for item in ruleset.get("nftables", []):
        if not isinstance(item, dict):
            continue
        rule = item.get("rule")
        if isinstance(rule, dict):
            found.append(rule)
    return found
