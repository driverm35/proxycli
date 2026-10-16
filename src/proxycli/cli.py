from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from proxycli import __version__
from proxycli.doctor import run_doctor
from proxycli.errors import ProxyCLIError, ValidationError
from proxycli.managers.nft import FirewallService
from proxycli.managers.stack import Stack
from proxycli.managers.update import apply_update, check_update
from proxycli.services.probes import (
    http_proxy_status,
    probe_public_https,
    probe_upstream,
    socks5_noauth_rejected,
)
from proxycli.services.store import password_from_file
from proxycli.ui.console import CLEARTEXT_WARNING, curl_example, socks_example
from proxycli.ui.status import plain_status
from proxycli.utils.validation import validate_password


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        return int(args.func(args))
    except ValidationError as exc:
        _fail(exc)
        return 2
    except ProxyCLIError as exc:
        _fail(exc)
        return 1
    except KeyboardInterrupt:
        print()
        return 130


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="proxycli", description="ProxyCLI")
    parser.set_defaults(func=cmd_default, json=False, timeout=5.0)
    sub = parser.add_subparsers(dest="command")

    version = sub.add_parser("version", help="версия")
    version.set_defaults(func=cmd_version)
    status = sub.add_parser("status", help="состояние")
    status.add_argument("--json", action="store_true")
    status.set_defaults(func=cmd_status)
    doctor = sub.add_parser("doctor", help="диагностика")
    doctor.add_argument("--json", action="store_true")
    doctor.add_argument("--timeout", type=float, default=5.0)
    doctor.set_defaults(func=cmd_doctor)
    update = sub.add_parser("update", help="обновление")
    update.add_argument("--check", action="store_true")
    update.add_argument("--apply", action="store_true")
    update.set_defaults(func=cmd_update)
    wizard = sub.add_parser("wizard", help="мастер без TTY")
    wizard.add_argument("--public-ip", required=True)
    wizard.add_argument("--domain", required=True)
    wizard.add_argument("--tls-mode", choices=("http", "dns"), default="http")
    wizard.add_argument("--acme-email", required=True)
    wizard.add_argument("--cloudflare-token-file")
    wizard.add_argument("--accept-dns", action="store_true")
    wizard.add_argument("--skip-probes", action="store_true")
    wizard.set_defaults(func=cmd_wizard)

    routes = sub.add_parser("routes")
    routes_sub = routes.add_subparsers(dest="routes_cmd", required=True)
    routes_list = routes_sub.add_parser("list")
    routes_list.set_defaults(func=cmd_routes_list)
    routes_add = routes_sub.add_parser("add")
    _route_flags(routes_add, cmd_routes_add)
    routes_edit = routes_sub.add_parser("edit")
    _route_flags(routes_edit, cmd_routes_edit)
    routes_rm = routes_sub.add_parser("remove")
    routes_rm.add_argument("--subdomain", required=True)
    routes_rm.set_defaults(func=cmd_routes_remove)
    routes_check = routes_sub.add_parser("check")
    routes_check.add_argument("--subdomain", required=True)
    routes_check.add_argument("--timeout", type=float, default=5.0)
    routes_check.set_defaults(func=cmd_routes_check)

    _proxy_parser(sub, "socks")
    _proxy_parser(sub, "http")

    backup = sub.add_parser("backup")
    backup_sub = backup.add_subparsers(dest="backup_cmd", required=True)
    backup_create = backup_sub.add_parser("create")
    backup_create.set_defaults(func=cmd_backup_create)
    backup_list = backup_sub.add_parser("list")
    backup_list.set_defaults(func=cmd_backup_list)
    backup_restore = backup_sub.add_parser("restore")
    backup_restore.add_argument("--id", required=True)
    backup_restore.set_defaults(func=cmd_backup_restore)

    settings = sub.add_parser("settings")
    settings_sub = settings.add_subparsers(dest="settings_cmd", required=True)
    settings_show = settings_sub.add_parser("show")
    settings_show.set_defaults(func=cmd_settings_show)
    prepare = settings_sub.add_parser("prepare-dns")
    prepare.set_defaults(func=cmd_prepare_dns)
    set_domain = settings_sub.add_parser("set-domain")
    set_domain.add_argument("--domain", required=True)
    set_domain.set_defaults(func=cmd_set_domain)
    set_ip = settings_sub.add_parser("set-ip")
    set_ip.add_argument("--public-ip", required=True)
    set_ip.set_defaults(func=cmd_set_ip)

    firewall = sub.add_parser("firewall")
    firewall_sub = firewall.add_subparsers(dest="firewall_cmd", required=True)
    firewall_plan = firewall_sub.add_parser("plan")
    firewall_plan.set_defaults(func=cmd_firewall_plan)
    firewall_apply = firewall_sub.add_parser("apply")
    firewall_apply.set_defaults(func=cmd_firewall_apply)
    firewall_rollback = firewall_sub.add_parser("rollback")
    firewall_rollback.set_defaults(func=cmd_firewall_rollback)

    logs = sub.add_parser("logs")
    logs.add_argument("--tail", type=int, default=50)
    logs.set_defaults(func=cmd_logs)
    restart = sub.add_parser("restart")
    restart.set_defaults(func=cmd_restart)
    return parser


def _route_flags(parser: argparse.ArgumentParser, func) -> None:
    parser.add_argument("--subdomain", required=True)
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--trust-private", action="store_true")
    parser.add_argument("--skip-probes", action="store_true")
    parser.set_defaults(func=func)


def _proxy_parser(sub: argparse._SubParsersAction, kind: str) -> None:
    parser = sub.add_parser(kind)
    commands = parser.add_subparsers(dest=f"{kind}_cmd", required=True)
    status = commands.add_parser("status")
    status.set_defaults(func=cmd_proxy_status, kind=kind)
    add = commands.add_parser("add-user")
    add.add_argument("--username", required=True)
    add.add_argument("--password")
    add.add_argument("--password-file")
    add.add_argument("--password-stdin", action="store_true")
    add.set_defaults(func=cmd_add_user, kind=kind)
    remove = commands.add_parser("remove-user")
    remove.add_argument("--username", required=True)
    remove.set_defaults(func=cmd_remove_user, kind=kind)
    configure = commands.add_parser("set")
    configure.add_argument("--port", type=int)
    configure.add_argument("--allow", action="append", default=[])
    configure.add_argument("--clear-allow", action="store_true")
    configure.add_argument("--enable", action="store_true")
    configure.add_argument("--disable", action="store_true")
    configure.set_defaults(func=cmd_proxy_set, kind=kind)
    test = commands.add_parser("test")
    test.set_defaults(func=cmd_proxy_test, kind=kind)
    example = commands.add_parser("example")
    example.add_argument("--username")
    example.set_defaults(func=cmd_proxy_example, kind=kind)
    reveal = commands.add_parser("reveal")
    reveal.add_argument("--username", required=True)
    reveal.add_argument("--i-understand", action="store_true")
    reveal.set_defaults(func=cmd_reveal, kind=kind)


def cmd_default(_args: argparse.Namespace) -> int:
    if sys.stdin.isatty() and sys.stdout.isatty():
        from proxycli.ui.menu import run_main_menu

        return run_main_menu()
    return cmd_status(argparse.Namespace(json=False))


def cmd_version(_args: argparse.Namespace) -> int:
    print(__version__)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    stack = Stack()
    config = stack.store.load()
    if args.json:
        print(
            json.dumps(
                {
                    "version": __version__,
                    "caddy": stack.container_state("proxycli-caddy"),
                    "routes": len(config.routes),
                    "domain": config.wildcard_domain,
                    "tls_mode": config.tls.mode,
                    "dns_plugin_ready": config.tls.dns_plugin_ready,
                    "text": plain_status(stack),
                },
                ensure_ascii=False,
            )
        )
    else:
        print(plain_status(stack))
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    results = run_doctor(Stack(), timeout=args.timeout)
    if args.json:
        print(json.dumps([item.to_dict() for item in results], ensure_ascii=False))
    else:
        for item in results:
            print(f"[{item.status}] {item.name}: {item.detail}")
            if item.cause:
                print(f"  причина: {item.cause}")
            if item.fix:
                print(f"  что сделать: {item.fix}")
    return 1 if any(item.status == "fail" for item in results) else 0


def cmd_update(args: argparse.Namespace) -> int:
    stack = Stack()
    if args.apply:
        print(apply_update(stack))
        return 0
    print(check_update(stack))
    return 0


def cmd_wizard(args: argparse.Namespace) -> int:
    token = ""
    if args.cloudflare_token_file:
        token = Path(args.cloudflare_token_file).read_text(encoding="utf-8").strip()
    warnings = Stack().save_wizard(
        public_ip=args.public_ip,
        domain=args.domain,
        tls_mode=args.tls_mode,
        acme_email=args.acme_email,
        token=token,
        accept_dns=args.accept_dns,
        probe=not args.skip_probes,
    )
    for warning in warnings:
        print(warning)
    print("Мастер сохранён. Успех публичного TLS этим сообщением не подтверждается.")
    return 0


def cmd_routes_list(_args: argparse.Namespace) -> int:
    config = Stack().store.load()
    for route in config.routes:
        print(f"{route.subdomain}\t{route.upstream}\ttrust_private={route.trust_private}")
    return 0


def cmd_routes_add(args: argparse.Namespace) -> int:
    warnings = Stack().add_route(
        args.subdomain,
        args.upstream,
        trust_private=args.trust_private,
        probe=not args.skip_probes,
    )
    _warnings(warnings)
    print("Маршрут записан. Публичный TLS успешен только если проверка не была пропущена и прошла.")
    return 0


def cmd_routes_edit(args: argparse.Namespace) -> int:
    warnings = Stack().edit_route(
        args.subdomain,
        args.upstream,
        trust_private=args.trust_private,
        probe=not args.skip_probes,
    )
    _warnings(warnings)
    return 0


def cmd_routes_remove(args: argparse.Namespace) -> int:
    _warnings(Stack().remove_route(args.subdomain))
    return 0


def cmd_routes_check(args: argparse.Namespace) -> int:
    stack = Stack()
    config = stack.store.load()
    route = config.route(args.subdomain)
    if route is None:
        raise ProxyCLIError(f"маршрут {args.subdomain} не найден")
    if stack.offline():
        print("Проверка пропущена (offline), успех не заявляется")
        return 0
    upstream = probe_upstream(route.upstream, args.timeout, trust_private=route.trust_private)
    public = probe_public_https(config.hostname(route.subdomain), config.public_ipv4, args.timeout)
    print("upstream: " + upstream.summary())
    print("public: " + public.summary())
    return 0 if upstream.ok and public.ok else 1


def cmd_proxy_status(args: argparse.Namespace) -> int:
    config = Stack().store.load()
    listener = config.socks if args.kind == "socks" else config.http
    print(f"enabled={listener.enabled} port={listener.port} users={len(listener.users)}")
    if args.kind == "http":
        print(CLEARTEXT_WARNING)
    return 0


def cmd_add_user(args: argparse.Namespace) -> int:
    secret, warnings = Stack().add_user(args.kind, args.username, _read_password(args))
    _warnings(warnings)
    print(f"Пользователь: {args.username}")
    print(f"Пароль (показывается один раз): {secret}")
    return 0


def cmd_remove_user(args: argparse.Namespace) -> int:
    _warnings(Stack().remove_user(args.kind, args.username))
    return 0


def cmd_proxy_set(args: argparse.Namespace) -> int:
    if args.enable and args.disable:
        raise ValidationError("укажите только --enable или --disable")
    enabled = True if args.enable else False if args.disable else None
    allow = [] if args.clear_allow else (args.allow or None)
    _warnings(Stack().configure_listener(args.kind, port=args.port, allowlist=allow, enabled=enabled))
    return 0


def cmd_proxy_test(args: argparse.Namespace) -> int:
    stack = Stack()
    if stack.offline():
        print("Проверка прокси пропущена (offline), успех не заявляется")
        return 0
    config = stack.store.load()
    listener = config.socks if args.kind == "socks" else config.http
    if args.kind == "socks":
        rejected = socks5_noauth_rejected("127.0.0.1", listener.port, 5)
        print("анонимный доступ отклонён" if rejected else "ОПАСНО: анонимный доступ открыт")
        return 0 if rejected else 1
    status = http_proxy_status("127.0.0.1", listener.port, "1.1.1.1", 443, 5)
    print(f"CONNECT без пароля: {status}")
    print(CLEARTEXT_WARNING)
    return 0 if status == 407 else 1


def cmd_proxy_example(args: argparse.Namespace) -> int:
    stack = Stack()
    config = stack.store.load()
    listener = config.socks if args.kind == "socks" else config.http
    username = args.username or (listener.users[0].username if listener.users else "USER")
    if args.kind == "http":
        print(CLEARTEXT_WARNING)
        print(curl_example(config.public_ipv4, listener.port, username))
    else:
        print(socks_example(config.public_ipv4, listener.port, username))
    return 0


def cmd_reveal(args: argparse.Namespace) -> int:
    if not args.i_understand and not sys.stdout.isatty():
        raise ProxyCLIError("отказ печатать пароль не в TTY", fix="добавьте --i-understand")
    stack = Stack()
    config = stack.store.load()
    listener = config.socks if args.kind == "socks" else config.http
    user = listener.user(args.username)
    if user is None:
        raise ProxyCLIError("пользователь не найден")
    secret = stack.store.load_secrets().get(user.secret_ref, "")
    validate_password(secret)
    stack.events.write(f"{args.kind}.reveal", username=args.username)
    print(secret)
    return 0


def cmd_backup_create(_args: argparse.Namespace) -> int:
    print(Stack().backup.create("manual"))
    return 0


def cmd_backup_list(_args: argparse.Namespace) -> int:
    for item in Stack().backup.list_ids():
        print(item)
    return 0


def cmd_backup_restore(args: argparse.Namespace) -> int:
    stack = Stack()
    safety = stack.backup.create("before-restore")
    try:
        stack.backup.restore(args.id)
        stack.reload(probe=False)
    except Exception:
        stack.backup.restore(safety)
        stack.reload(probe=False, simulate_failure=False)
        raise
    print(f"восстановлено {args.id}")
    return 0


def cmd_settings_show(_args: argparse.Namespace) -> int:
    print(plain_status(Stack()))
    return 0


def cmd_prepare_dns(_args: argparse.Namespace) -> int:
    ready, message = Stack().prepare_dns_plugin()
    print(message)
    if not ready:
        print("wildcard TLS не заявляется")
        return 1
    return 0


def cmd_set_domain(args: argparse.Namespace) -> int:
    from proxycli.utils.validation import validate_domain

    stack = Stack()
    domain = validate_domain(args.domain)

    def mutate() -> None:
        config = stack.store.load()
        config.wildcard_domain = domain
        config.dns_ok = None
        config.dns_detail = "домен изменён, DNS заново не подтверждён"
        stack.store.save(config)

    _warnings(stack.transaction("settings-domain", mutate, probe=False))
    return 0


def cmd_set_ip(args: argparse.Namespace) -> int:
    from proxycli.utils.validation import validate_public_ipv4

    stack = Stack()
    ip = validate_public_ipv4(args.public_ip)

    def mutate() -> None:
        config = stack.store.load()
        config.public_ipv4 = ip
        stack.store.save(config)

    _warnings(stack.transaction("settings-ip", mutate, probe=False))
    return 0


def cmd_firewall_plan(_args: argparse.Namespace) -> int:
    print(FirewallService(Stack()).describe())
    return 0


def cmd_firewall_apply(_args: argparse.Namespace) -> int:
    print(FirewallService(Stack()).apply())
    return 0


def cmd_firewall_rollback(_args: argparse.Namespace) -> int:
    print(FirewallService(Stack()).rollback())
    return 0


def cmd_logs(args: argparse.Namespace) -> int:
    for row in Stack().events.tail(args.tail):
        print(json.dumps(row, ensure_ascii=False))
    return 0


def cmd_restart(_args: argparse.Namespace) -> int:
    stack = Stack()
    if stack.offline():
        print("перезапуск пропущен (offline), успех не заявляется")
        return 0
    _warnings(stack.reload(probe=False))
    return 0


def _read_password(args: argparse.Namespace) -> str | None:
    selected = [bool(args.password), bool(args.password_file), bool(args.password_stdin)]
    if sum(selected) > 1:
        raise ValidationError("передайте пароль только одним способом")
    if args.password_stdin:
        return validate_password(sys.stdin.readline().rstrip("\n"))
    if args.password_file:
        return password_from_file(Path(args.password_file))
    if args.password:
        print("Предупреждение: пароль в аргументах виден в списке процессов", file=sys.stderr)
        return validate_password(args.password)
    return None


def _warnings(warnings: list[str]) -> None:
    for warning in warnings:
        print(warning)


def _fail(exc: ProxyCLIError) -> None:
    print(f"Ошибка: {exc}", file=sys.stderr)
    if exc.fix:
        print(f"Что сделать: {exc.fix}", file=sys.stderr)
