from __future__ import annotations

from proxycli.errors import ProxyCLIError
from proxycli.managers.firewall import (
    command_is_unsafe,
    managed_ports,
    parse_ruleset,
    plan_apply,
    plan_rollback,
)
from proxycli.managers.stack import Stack
from proxycli.utils.proc import require_ok


class FirewallService:
    def __init__(self, stack: Stack) -> None:
        self.stack = stack

    def describe(self) -> str:
        if self.stack.offline():
            return "firewall не проверялся (offline), успех не заявляется"
        ruleset = self._ruleset()
        _commands, note = plan_apply(ruleset, managed_ports(self.stack.store.load()))
        return note or "план пуст: нужные правила уже есть или их некуда безопасно добавить"

    def apply(self) -> str:
        self._refuse_offline()
        config = self.stack.store.load()
        commands, note = plan_apply(self._ruleset(), managed_ports(config))
        for argv in commands:
            if command_is_unsafe(argv):
                raise ProxyCLIError("отказ: команда затронула бы SSH или сделала бы flush")
            require_ok(self.stack.runner(argv, timeout=15), argv)
        config.firewall_managed = True
        self.stack.store.save(config)
        self.stack.events.write("firewall.apply", rules=len(commands))
        if commands:
            return f"добавлено правил: {len(commands)}"
        return note or "изменения не потребовались"

    def rollback(self) -> str:
        self._refuse_offline()
        commands = plan_rollback(self._ruleset())
        for argv in commands:
            if "flush" in argv or "ruleset" in argv:
                raise ProxyCLIError("отказ: откат не делает flush")
            require_ok(self.stack.runner(argv, timeout=15), argv)
        config = self.stack.store.load()
        config.firewall_managed = False
        self.stack.store.save(config)
        self.stack.events.write("firewall.rollback", rules=len(commands))
        return f"удалено правил proxycli: {len(commands)}"

    def _ruleset(self) -> dict:
        argv = ["nft", "-j", "list", "ruleset"]
        result = require_ok(self.stack.runner(argv, timeout=15), argv)
        return parse_ruleset(result.stdout)

    def _refuse_offline(self) -> None:
        if self.stack.offline():
            raise ProxyCLIError(
                "firewall не применяется в PROXYCLI_OFFLINE",
                fix="запустите команду на VPS без PROXYCLI_OFFLINE",
            )
