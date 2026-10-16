from __future__ import annotations

from proxycli.errors import ProxyCLIError
from proxycli.managers.stack import Stack
from proxycli.services.probes import detect_public_ipv4
from proxycli.ui.console import DNS_HELP, console
from proxycli.ui.prompts import ask_confirm, ask_secret, ask_text, choose


def run_wizard(stack: Stack | None = None) -> int:
    stack = stack or Stack()
    out = console()
    out.print("Мастер первого запуска ProxyCLI")
    out.print(DNS_HELP)
    detected = "" if stack.offline() else (detect_public_ipv4() or "")
    if detected:
        out.print(f"Обнаружен публичный IPv4: {detected}. Это не проверка TLS.")
    else:
        out.print("Публичный IPv4 автоматически не подтверждён.")
    ip = ask_text("Публичный IPv4", detected)
    domain = ask_text("Домен для поддоменов, без звёздочки", "hooks.example.com")
    email = ask_text("Email ACME", "admin@example.com")
    mode_key = choose(
        "Режим TLS",
        [("http", "A: сертификат на каждый хост"), ("dns", "B: wildcard DNS-01 Cloudflare")],
    )
    if not ip or not domain or not email or mode_key is None:
        out.print("Мастер отменён, конфиг не записан.")
        return 1
    token = ""
    if mode_key == "dns":
        out.print("Токен не будет показан снова и не попадёт в журнал.")
        token = ask_secret("Токен Cloudflare") or ""
        if not token:
            out.print("Токен пуст. Режим B не сохранён.")
            return 1
    accept = True
    if not stack.offline():
        accept = ask_confirm("Продолжить, даже если проверка DNS не совпадёт?", default=False)
    try:
        warnings = stack.save_wizard(
            public_ip=ip,
            domain=domain,
            tls_mode=mode_key,
            acme_email=email,
            token=token,
            accept_dns=accept,
            probe=not stack.offline(),
        )
    except ProxyCLIError as exc:
        out.print(f"Ошибка: {exc}")
        if exc.fix:
            out.print(f"Что сделать: {exc.fix}")
        return 1
    for warning in warnings:
        out.print(warning)
    out.print("Мастер сохранён. Публичный TLS успешен только если doctor покажет сертификат ok.")
    return 0
