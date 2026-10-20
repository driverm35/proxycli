"""Russian main menu. Esc goes back, Ctrl+C exits."""

from __future__ import annotations

from proxycli.doctor import run_doctor
from proxycli.errors import ProbeError, ProxyCLIError, ValidationError
from proxycli.managers.stack import Stack
from proxycli.ui.console import (
    CLEARTEXT_WARNING,
    console,
    copy_secret,
    curl_example,
    format_user_list,
    reveal_user,
    route_added_text,
    socks_example,
)
from proxycli.ui.prompts import ask_confirm, ask_text, choose, pause
from proxycli.ui.status import plain_status
from proxycli.ui.wizard import run_wizard
from proxycli.utils.validation import (
    upstream_is_forbidden,
    upstream_requires_trust,
    validate_subdomain,
    validate_upstream,
)


def _show_until_enter(out, text: str) -> None:
    out.print(text, markup=False, highlight=False)
    pause()


def run_main_menu() -> int:
    stack = Stack()
    out = console()
    if not stack.store.load().first_run_complete:
        out.print("Первичная настройка ещё не выполнена.")
        if ask_confirm("Запустить мастер?", default=True):
            run_wizard(stack)
    actions = [
        ("routes", "Вебхуки и маршруты"),
        ("socks", "SOCKS5"),
        ("http", "HTTP-прокси"),
        ("doctor", "Диагностика"),
        ("settings", "Настройки"),
        ("update", "Обновление ProxyCLI"),
        ("events", "Журнал событий"),
        ("exit", "Выход"),
    ]
    while True:
        out.print(plain_status(stack))
        choice = choose("Главное меню", actions)
        if choice in {None, "exit"}:
            out.print("Выход.")
            return 0
        try:
            if choice == "routes":
                _routes(stack)
            elif choice == "socks":
                _users(stack, "socks")
            elif choice == "http":
                _users(stack, "http")
            elif choice == "doctor":
                for item in run_doctor(stack, timeout=5):
                    out.print(f"[{item.status}] {item.name}: {item.detail}")
                    if item.fix:
                        out.print(f"    {item.fix}")
            elif choice == "settings":
                run_wizard(stack)
            elif choice == "update":
                out.print("Обновление: sudo proxycli update --apply")
            elif choice == "events":
                for row in stack.events.tail(30):
                    out.print(f"{row.get('ts', '')} {row.get('event', '')}")
        except ProxyCLIError as exc:
            out.print(f"Ошибка: {exc}")
            if exc.fix:
                out.print(f"Что сделать: {exc.fix}")
        except KeyboardInterrupt:
            out.print("Выход.")
            return 130
        pause()
    return 0


def _routes(stack: Stack) -> None:
    out = console()
    while True:
        choice = choose(
            "Вебхуки и маршруты",
            [
                ("add", "Добавить"),
                ("list", "Список"),
                ("check", "Проверить все"),
                ("back", "Назад"),
            ],
        )
        if choice in {None, "back"}:
            return
        if choice == "list":
            for route in stack.store.load().routes:
                out.print(f"{route.subdomain}  {route.upstream}  enabled={route.enabled}")
            continue
        if choice == "check":
            out.print("Проверка: proxycli routes check --subdomain ИМЯ")
            continue
        subdomain = ask_text("Поддомен")
        upstream = ask_text("URL апстрима")
        if not subdomain or not upstream:
            return
        validate_subdomain(subdomain)
        origin = validate_upstream(upstream)
        if upstream_is_forbidden(origin):
            raise ValidationError(
                "апстрим на loopback, link-local или metadata запрещён",
                fix="эти адреса нельзя использовать даже с --trust-private",
            )
        trusted = False
        if upstream_requires_trust(origin):
            trusted = ask_confirm("Подтвердить приватный апстрим (trusted-private)?", default=False)
        try:
            warnings = stack.add_route(
                subdomain,
                upstream,
                trust_private=trusted,
                probe=not stack.offline(),
            )
        except ProbeError as exc:
            if exc.layer == "policy":
                raise
            out.print(f"Предупреждение: {exc}")
            if not ask_confirm("Сохранить маршрут неактивным?", default=False):
                out.print("Маршрут не сохранён.")
                continue
            warnings = stack.add_route(
                subdomain,
                upstream,
                trust_private=trusted,
                probe=False,
                inactive=True,
            )
        for warning in warnings:
            out.print(warning)
        saved = stack.store.load().route(validate_subdomain(subdomain))
        if saved is not None:
            config = stack.store.load()
            out.print(route_added_text(config.hostname(saved.subdomain), saved.upstream))


def _users(stack: Stack, kind: str) -> None:
    out = console()
    if kind == "http":
        out.print(CLEARTEXT_WARNING)
    while True:
        choice = choose(
            "SOCKS5" if kind == "socks" else "HTTP-прокси",
            [
                ("add", "Создать пользователя"),
                ("list", "Список"),
                ("reveal", "Показать пароль"),
                ("delete", "Удалить"),
                ("back", "Назад"),
            ],
        )
        if choice in {None, "back"}:
            return
        config = stack.store.load()
        listener = config.socks if kind == "socks" else config.http
        if choice == "list":
            _show_until_enter(out, format_user_list(kind, config))
            continue
        username = ask_text("Имя пользователя")
        if not username:
            return
        if choice == "add":
            password, warnings = stack.add_user(kind, username, None)
            for warning in warnings:
                out.print(warning, markup=False, highlight=False)
            host = config.public_ipv4 or "SERVER_IP"
            if kind == "http":
                out.print(curl_example(host, listener.port, username), markup=False, highlight=False)
            else:
                out.print(socks_example(host, listener.port, username), markup=False, highlight=False)
            out.print(f"Пароль (скопируйте строку): {password}", markup=False, highlight=False)
            copy_secret(password)
            pause()
            continue
        if choice == "reveal":
            if stack.store.layout.secrets_file.exists():
                secrets = stack.store.load_secrets()
            else:
                secrets = None
            text = reveal_user(kind, username, config, secrets)
            out.print(text, markup=False, highlight=False)
            if text.startswith("Пароль:"):
                stack.events.write(f"{kind}.reveal", username=username)
            pause()
            continue
        if choice == "delete" and ask_confirm(f"Удалить {username}?", default=False):
            stack.remove_user(kind, username)
            _show_until_enter(out, "Удалено.")
