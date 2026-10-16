from __future__ import annotations

import sys

from prompt_toolkit.application import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout
from prompt_toolkit.layout.containers import Window
from prompt_toolkit.layout.controls import FormattedTextControl

from proxycli.ui.status import interactive


def choose(title: str, options: list[tuple[str, str]]) -> str | None:
    if interactive():
        try:
            return _choose_keys(title, options)
        except (EOFError, KeyboardInterrupt):
            return None
        except Exception:
            return _choose_plain(title, options)
    return _choose_plain(title, options)


def ask_text(label: str, default: str = "") -> str | None:
    if interactive():
        import questionary

        return questionary.text(label, default=default).ask()
    suffix = f" [{default}]" if default else ""
    typed = input(f"{label}{suffix}: ").strip()
    return typed or default


def ask_secret(label: str) -> str | None:
    if interactive():
        import questionary

        return questionary.password(label).ask()
    return input(f"{label}: ").strip()


def ask_confirm(label: str, *, default: bool = False) -> bool:
    if interactive():
        import questionary

        answer = questionary.confirm(label, default=default).ask()
        return bool(answer)
    hint = "Y/n" if default else "y/N"
    typed = input(f"{label} [{hint}]: ").strip().lower()
    if not typed:
        return default
    return typed in {"y", "yes", "д", "да"}


def _choose_plain(title: str, options: list[tuple[str, str]]) -> str | None:
    print(title)
    for index, (_key, label) in enumerate(options, start=1):
        print(f"  {index}. {label}")
    print("  0. Назад")
    typed = input("> ").strip()
    if typed in {"", "0"}:
        return None
    if not typed.isdigit():
        return None
    index = int(typed) - 1
    if index < 0 or index >= len(options):
        return None
    return options[index][0]


def _choose_keys(title: str, options: list[tuple[str, str]]) -> str | None:
    selected = {"index": 0}
    result: dict[str, str | None] = {"value": None}

    def render() -> str:
        lines = [title, ""]
        for index, (_key, label) in enumerate(options):
            mark = ">" if index == selected["index"] else " "
            lines.append(f" {mark} {label}")
        lines.extend(["", "Стрелки, Enter, Esc, Ctrl+C"])
        return "\n".join(lines)

    bindings = KeyBindings()

    @bindings.add("up")
    def _up(event) -> None:
        selected["index"] = (selected["index"] - 1) % len(options)
        event.app.invalidate()

    @bindings.add("down")
    def _down(event) -> None:
        selected["index"] = (selected["index"] + 1) % len(options)
        event.app.invalidate()

    @bindings.add("enter")
    def _enter(event) -> None:
        result["value"] = options[selected["index"]][0]
        event.app.exit()

    @bindings.add("escape")
    def _escape(event) -> None:
        result["value"] = None
        event.app.exit()

    @bindings.add("c-c")
    def _interrupt(event) -> None:
        result["value"] = None
        event.app.exit(exception=KeyboardInterrupt())

    application = Application(
        layout=Layout(Window(FormattedTextControl(render))),
        key_bindings=bindings,
        full_screen=False,
    )
    application.run()
    return result["value"]


def pause() -> None:
    if sys.stdin.isatty():
        input("Enter, чтобы продолжить ")
