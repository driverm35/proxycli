"""Russian main menu. Esc goes back, Ctrl+C exits."""

from __future__ import annotations

from proxycli.doctor import run_doctor
from proxycli.errors import ProxyCLIError
from proxycli.managers.stack import Stack
from proxycli.ui.console import CLEARTEXT_WARNING, console, copy_secret, curl_example, socks_example
from proxycli.ui.prompts import ask_confirm, ask_text, choose, pause
from proxycli.ui.status import plain_status
from proxycli.ui.wizard import run_wizard


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
        trusted = ask_confirm("Подтвердить приватный апстрим (trusted-private)?", default=False)
        warnings = stack.add_route(subdomain, upstream, trust_private=trusted, probe=not stack.offline())
        for warning in warnings:
            out.print(warning)


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
            for user in listener.users:
                out.print(f"{user.username}  порт {listener.port}")
            continue
        username = ask_text("Имя пользователя")
        if not username:
            return
        if choice == "add":
            password, warnings = stack.add_user(kind, username, None)
            for warning in warnings:
                out.print(warning)
            host = config.public_ipv4 or "SERVER_IP"
            if kind == "http":
                out.print(curl_example(host, listener.port, username))
            else:
                out.print(socks_example(host, listener.port, username))
            if not copy_secret(password):
                out.print(f"Пароль (скопируйте строку): {password}")
            continue
        if choice == "reveal":
            user = listener.user(username)
            if user is None:
                out.print("Пользователь не найден.")
                continue
            secret = stack.store.load_secrets().get(user.secret_ref, "")
            stack.events.write(f"{kind}.reveal", username=username)
            if not copy_secret(secret):
                out.print(f"Пароль (скопируйте строку): {secret}")
            continue
        if choice == "delete" and ask_confirm(f"Удалить {username}?", default=False):
            stack.remove_user(kind, username)
            out.print("Удалено.")
