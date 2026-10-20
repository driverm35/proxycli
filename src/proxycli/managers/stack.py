from __future__ import annotations

import itertools
import os
import uuid
from datetime import datetime

from proxycli.constants import (
    CADDY_ADMIN,
    CADDY_CONTAINER,
    CADDY_DNS_IMAGE,
    CADDY_DNS_MODULE,
    CADDY_IMAGE,
    PROXY_CONTAINER,
)
from proxycli.errors import ProbeError, ProxyCLIError, RollbackError, ValidationError
from proxycli.managers.backup import BackupManager
from proxycli.models.config import AppConfig, ProxyUser, Route
from proxycli.services import proxyacl
from proxycli.services.caddyfile import (
    WILDCARD_FALLBACK,
    assert_caddyfile_contains_routes,
    render_caddyfile,
)
from proxycli.services.compose import ENTRYPOINT, render_compose, render_dockerfile
from proxycli.services.events import EventLog
from proxycli.services.probes import (
    check_name_dns,
    dns_not_saved_message,
    probe_public_https,
    probe_upstream,
)
from proxycli.services.proxy3cfg import _active, render_3proxy
from proxycli.services.store import Store, generate_password
from proxycli.utils.files import atomic_write, chmod
from proxycli.utils.paths import PathLayout
from proxycli.utils.proc import OfflineRunner, ProcResult, Runner, make_runner, require_ok
from proxycli.utils.validation import (
    secret_ref,
    upstream_is_forbidden,
    upstream_is_private_literal,
    validate_allowlist,
    validate_domain,
    validate_email,
    validate_password,
    validate_port,
    validate_public_ipv4,
    validate_subdomain,
    validate_token,
    validate_upstream,
    validate_username,
)


class Stack:
    def __init__(self, layout: PathLayout | None = None, runner: Runner | None = None) -> None:
        self.layout = layout or PathLayout.from_env()
        self.runner = runner or make_runner()
        self.store = Store(self.layout)
        self.backup = BackupManager(self.layout)
        self.events = EventLog(self.layout, self.store)
        self._proxy_restarted = False
        self._proxy_cfg_changed = False

    def offline(self) -> bool:
        return isinstance(self.runner, OfflineRunner) or os.environ.get("PROXYCLI_OFFLINE") == "1"

    def render(self) -> list[str]:
        config = self.store.load()
        secrets = self.store.load_secrets()
        caddy, warnings = render_caddyfile(config)
        proxy = render_3proxy(config, secrets)
        compose = render_compose(config, self.layout.token_file)
        assert_caddyfile_contains_routes(caddy, config)
        self._proxy_cfg_changed = self._write_runtime(caddy, proxy, compose)
        return warnings

    def reload(
        self,
        *,
        probe_hosts: list[str] | None = None,
        probe: bool = True,
        simulate_failure: bool = True,
        restart_proxy: bool = False,
    ) -> list[str]:
        warnings = self.render()
        if simulate_failure and self._fail_step() == "reload":
            raise ProxyCLIError("симулированный сбой reload", fix="proxycli backup list")
        if self.offline():
            warnings.append("offline: Docker и публичный TLS не проверялись, успех не заявляется")
            return warnings
        warnings.extend(self._docker_validate_and_reload())
        if restart_proxy or self._proxy_needs_recreate():
            self._recreate_proxy()
        if probe and probe_hosts and not self._skip_probes():
            config = self.store.load()
            for host in probe_hosts:
                report = probe_public_https(host, config.public_ipv4, timeout=8)
                if not report.ok:
                    failed = report.failed()
                    raise ProbeError(
                        report.summary(),
                        layer=failed.layer if failed else "tls",
                        fix=failed.fix if failed else "",
                    )
                if not any(item.layer == "tls" and item.status == "ok" for item in report.layers):
                    raise ProbeError("публичный TLS не подтверждён", layer="tls")
        elif probe and probe_hosts:
            warnings.append("публичная проверка пропущена, успех TLS не заявляется")
        return warnings

    def transaction(
        self,
        reason: str,
        mutate,
        *,
        probe_hosts: list[str] | None = None,
        probe: bool = False,
        restart_proxy: bool = False,
    ) -> list[str]:
        snap = self.backup.create(reason)
        try:
            mutate()
            return self.reload(probe_hosts=probe_hosts, probe=probe, restart_proxy=restart_proxy)
        except Exception as exc:
            self._rollback(snap, exc, reason=reason)
            raise

    def save_wizard(
        self,
        *,
        public_ip: str,
        domain: str,
        tls_mode: str,
        acme_email: str,
        token: str = "",
        accept_dns: bool = False,
        probe: bool = True,
    ) -> list[str]:
        ip = validate_public_ipv4(public_ip)
        zone = validate_domain(domain)
        email = validate_email(acme_email)
        if tls_mode not in {"http", "dns"}:
            raise ValidationError("режим TLS: http или dns")
        warnings: list[str] = []
        dns_ok: bool | None
        detail: str
        if not probe or self.offline() or self._skip_probes():
            dns_ok = None
            detail = "DNS не проверялся, успех не заявляется"
            warnings.append(detail)
        else:
            dns_ok, detail = check_name_dns(zone, ip, timeout=5)
            if not dns_ok and not accept_dns:
                raise ProbeError(
                    dns_not_saved_message(zone, ip, detail),
                    layer="dns",
                    fix="создайте A-запись на публичный IPv4 этого сервера и снова запустите sudo proxycli",
                )
            if not dns_ok:
                warnings.append(detail)
        ready = False
        if tls_mode == "dns":
            if not token:
                raise ValidationError(
                    "для режима B нужен токен Cloudflare",
                    fix="передайте файл токена; успех wildcard TLS без модуля не заявляется",
                )
            validate_token(token)
            ready, message = self.prepare_dns_plugin()
            warnings.append(message)
            if not ready:
                warnings.append(WILDCARD_FALLBACK)

        def mutate() -> None:
            if tls_mode == "dns":
                self.store.write_token(token)
            config = self.store.load()
            config.public_ipv4 = ip
            config.wildcard_domain = zone
            config.tls.mode = tls_mode  # type: ignore[assignment]
            config.tls.acme_email = email
            config.tls.dns_plugin_ready = ready
            config.first_run_complete = True
            config.dns_ok = dns_ok
            config.dns_detail = detail
            self.store.save(config)

        warnings.extend(self.transaction("wizard", mutate, probe=False))
        self.events.write("wizard.complete", domain=zone, tls_mode=tls_mode, dns_plugin_ready=ready)
        return warnings

    def prepare_dns_plugin(self) -> tuple[bool, str]:
        self.layout.ensure_dirs()
        atomic_write(self.layout.dockerfile, render_dockerfile(), 0o644)
        atomic_write(self.layout.entrypoint, ENTRYPOINT, 0o755)
        if self.offline():
            return False, "сборка Caddy с Cloudflare пропущена (offline); wildcard TLS не подтверждён"
        build = [
            "docker",
            "build",
            "-f",
            str(self.layout.dockerfile),
            "-t",
            CADDY_DNS_IMAGE,
            str(self.layout.dockerfile.parent),
        ]
        built = self.runner(build, timeout=600)
        if not built.ok:
            return False, "сборка образа Caddy с модулем Cloudflare не удалась; wildcard TLS не выпущен"
        listed = self.runner(
            ["docker", "run", "--rm", CADDY_DNS_IMAGE, "caddy", "list-modules"],
            timeout=90,
        )
        if listed.ok and CADDY_DNS_MODULE in listed.stdout:
            return True, "модуль dns.providers.cloudflare подтверждён командой list-modules"
        return False, "list-modules не подтвердил dns.providers.cloudflare; wildcard TLS не заявляется"

    def add_route(
        self,
        subdomain: str,
        upstream: str,
        *,
        trust_private: bool,
        probe: bool,
        inactive: bool = False,
    ) -> list[str]:
        sub = validate_subdomain(subdomain)
        origin = validate_upstream(upstream)
        config = self._require_ready()
        if config.route(sub):
            raise ValidationError(f"маршрут {sub} уже есть")
        warning, confirmed = self._guard_upstream(
            origin,
            trust_private=trust_private,
            probe=probe,
            inactive=inactive,
        )
        host = config.hostname(sub)

        def mutate() -> None:
            current = self.store.load()
            current.routes.append(
                Route(
                    id=uuid.uuid4().hex,
                    subdomain=sub,
                    upstream=origin,
                    trust_private=trust_private,
                    enabled=True,
                )
            )
            self.store.save(current)

        warnings = [warning]
        warnings.extend(
            self.transaction(
                "route-add",
                mutate,
                probe_hosts=[host] if confirmed else None,
                probe=probe and confirmed,
            )
        )
        self.events.write("route.add", subdomain=sub, upstream=origin, trust_private=trust_private)
        return [item for item in warnings if item]

    def edit_route(
        self,
        subdomain: str,
        upstream: str,
        *,
        trust_private: bool,
        probe: bool,
        inactive: bool = False,
    ) -> list[str]:
        sub = validate_subdomain(subdomain)
        origin = validate_upstream(upstream)
        config = self._require_ready()
        if config.route(sub) is None:
            raise ValidationError(f"маршрут {sub} не найден")
        warning, confirmed = self._guard_upstream(
            origin,
            trust_private=trust_private,
            probe=probe,
            inactive=inactive,
        )
        host = config.hostname(sub)

        def mutate() -> None:
            current = self.store.load()
            route = current.route(sub)
            if route is None:
                raise ValidationError(f"маршрут {sub} не найден")
            route.upstream = origin
            route.trust_private = trust_private
            route.enabled = True
            self.store.save(current)

        warnings = [warning]
        warnings.extend(
            self.transaction(
                "route-edit",
                mutate,
                probe_hosts=[host] if confirmed else None,
                probe=probe and confirmed,
            )
        )
        self.events.write("route.edit", subdomain=sub, upstream=origin)
        return [item for item in warnings if item]

    def remove_route(self, subdomain: str) -> list[str]:
        sub = validate_subdomain(subdomain)
        if self._require_ready().route(sub) is None:
            raise ValidationError(f"маршрут {sub} не найден")

        def mutate() -> None:
            current = self.store.load()
            current.routes = [route for route in current.routes if route.subdomain != sub]
            self.store.save(current)

        warnings = self.transaction("route-remove", mutate, probe=False)
        self.events.write("route.remove", subdomain=sub)
        return warnings

    def add_user(self, kind: str, username: str, password: str | None) -> tuple[str, list[str]]:
        user = validate_username(username)
        secret = validate_password(password) if password else generate_password()
        ref = secret_ref(kind, user)
        listener_name = _kind(kind)

        def mutate() -> None:
            config = self.store.load()
            listener = getattr(config, listener_name)
            if listener.user(user):
                raise ValidationError(f"пользователь {user} уже есть")
            listener.users.append(ProxyUser(username=user, secret_ref=ref))
            listener.enabled = True
            self.store.save(config)
            self.store.set_secret(ref, secret)

        warnings = self.transaction(f"{kind}-user-add", mutate, probe=False)
        self.events.write(f"{kind}.user_add", username=user)
        return secret, warnings

    def remove_user(self, kind: str, username: str) -> list[str]:
        user = validate_username(username)
        ref = secret_ref(kind, user)
        listener_name = _kind(kind)

        def mutate() -> None:
            config = self.store.load()
            listener = getattr(config, listener_name)
            if listener.user(user) is None:
                raise ValidationError(f"пользователь {user} не найден")
            listener.users = [item for item in listener.users if item.username != user]
            if not listener.users:
                listener.enabled = False
            self.store.save(config)
            self.store.delete_secret(ref)

        warnings = self.transaction(f"{kind}-user-remove", mutate, probe=False)
        self.events.write(f"{kind}.user_remove", username=user)
        return warnings

    def configure_listener(
        self,
        kind: str,
        *,
        port: int | None = None,
        allowlist: list[str] | None = None,
        enabled: bool | None = None,
    ) -> list[str]:
        listener_name = _kind(kind)

        def mutate() -> None:
            config = self.store.load()
            listener = getattr(config, listener_name)
            if port is not None:
                listener.port = validate_port(port, kind=kind)
            if allowlist is not None:
                listener.allowlist = validate_allowlist(allowlist)
            if enabled is not None:
                if enabled and not listener.users:
                    raise ValidationError(
                        "нельзя включить прокси без пользователей",
                        fix=f"proxycli {kind} add-user --username NAME",
                    )
                listener.enabled = enabled
            self.store.save(config)

        warnings = self.transaction(f"{kind}-configure", mutate, probe=False)
        self.events.write(f"{kind}.configure")
        return warnings

    def allow_source(self, kind: str, username: str, cidr: str) -> list[str]:
        """Append one client IP or CIDR. Does not rotate or read the password."""
        user = validate_username(username)
        entry = validate_allowlist([cidr])[0]
        listener_name = _kind(kind)
        current = self.store.load()
        listener = getattr(current, listener_name)
        if listener.user(user) is None:
            raise ValidationError(
                f"пользователь {user} не найден",
                fix=f"proxycli {kind} add-user --username {user}",
            )
        if entry in listener.allowlist:
            warnings = self.transaction(f"{kind}-allow", lambda: None, probe=False, restart_proxy=True)
            warnings.append(f"{entry} уже в allowlist; 3proxy перезапущен с текущим конфигом. Пароль не менялся.")
            return warnings

        def mutate() -> None:
            config = self.store.load()
            target = getattr(config, listener_name)
            if target.user(user) is None:
                raise ValidationError(f"пользователь {user} не найден")
            if entry not in target.allowlist:
                target.allowlist.append(entry)
            self.store.save(config)

        warnings = self.transaction(f"{kind}-allow", mutate, probe=False, restart_proxy=True)
        self.events.write(f"{kind}.allow", username=user, cidr=entry)
        warnings.append("Пароль не менялся.")
        return warnings

    def inspect_acl(self, kind: str, source: str | None = None, tail: int = 2000) -> list[str]:
        """Read-only report: allowlist, ACL without passwords, container and recent 3proxy log."""
        listener = getattr(self.store.load(), _kind(kind))
        out = [
            f"enabled={listener.enabled} port={listener.port} "
            f"users={','.join(user.username for user in listener.users) or '-'}",
            "allowlist (общий для всех пользователей этого прокси): "
            + (", ".join(listener.allowlist) or "пуст, источник не ограничен"),
        ]
        if source:
            address = validate_allowlist([source])[0]
            if "/" in address:
                raise ValidationError("для --source нужен один IP, не сеть")
            verdict = proxyacl.allowed_by(listener.allowlist, address)
            out.append(
                f"{address}: "
                + {True: "входит в allowlist", False: "НЕ входит в allowlist", None: "allowlist пуст"}[verdict]
            )
        cfg = self.layout.proxy_cfg
        if cfg.exists():
            out.append("ACL в 3proxy.cfg:")
            out.extend("  " + line for line in proxyacl.acl_lines(cfg.read_text(encoding="utf-8")))
        else:
            out.append("3proxy.cfg ещё не создан")
        if self.offline():
            out.append("Docker не проверялся (offline)")
            return out
        out.append(f"контейнер {PROXY_CONTAINER}: {self.container_state(PROXY_CONTAINER)}")
        stale = self.proxy_config_stale()
        if stale:
            out.append(
                "ВНИМАНИЕ: 3proxy.cfg новее контейнера, 3proxy работает со старым ACL. "
                "Исправление: sudo proxycli restart"
            )
        elif stale is False:
            out.append("контейнер запущен после последней записи 3proxy.cfg")
        gateway = self._proxy_gateway()
        if gateway:
            out.append(f"шлюз Docker-сети proxycli: {gateway}")
        out.append(self._dnat_note(listener.port))
        logs = self.runner(["docker", "logs", "--tail", str(tail), PROXY_CONTAINER], timeout=20)
        entries = proxyacl.parse_log(f"{logs.stdout}\n{logs.stderr}", listener.port) if logs.ok else []
        if not logs.ok:
            out.append("журнал 3proxy недоступен: docker logs завершился с ошибкой")
        elif not entries:
            out.append("в журнале 3proxy нет подключений к этому порту")
        else:
            out.append(f"последние подключения (из {len(entries)} строк журнала, пароли не пишутся):")
            out.extend("  " + row for row in proxyacl.summarize(entries))
            clients = {entry.client for entry in entries}
            if gateway and gateway in clients:
                out.append(
                    f"ВНИМАНИЕ: 3proxy видит адрес шлюза {gateway} вместо адреса клиента. "
                    "Docker не сохраняет источник (нет DNAT, работает userland-proxy), "
                    "поэтому allowlist по IP не сработает."
                )
            if source and address not in clients:
                out.append(
                    f"подключений с {address} в журнале нет: клиент выходит с другого IP "
                    "или пакеты не доходят до 3proxy (firewall, маршрут)"
                )
        return out

    def _proxy_gateway(self) -> str:
        result = self.runner(
            ["docker", "network", "inspect", "-f", "{{range .IPAM.Config}}{{.Gateway}} {{end}}", "proxycli"],
            timeout=8,
        )
        if not result.ok:
            return ""
        return next(iter(result.stdout.split()), "")

    def _dnat_note(self, port: int) -> str:
        try:
            result = self.runner(["iptables", "-t", "nat", "-S", "DOCKER"], timeout=8)
        except ProxyCLIError:
            return "DNAT Docker не проверен: нет iptables"
        if not result.ok:
            return "DNAT Docker не проверен: iptables -t nat -S DOCKER завершился с ошибкой"
        marker = f"--dport {port} "
        if any(marker in line and "DNAT" in line for line in result.stdout.splitlines()):
            return f"DNAT Docker для порта {port} есть: адрес клиента сохраняется"
        return (
            f"ВНИМАНИЕ: DNAT Docker для порта {port} в iptables не найден. Если Docker не использует "
            "nftables-бэкенд, подключения идут через userland-proxy и 3proxy видит адрес шлюза. "
            "Проверьте /etc/docker/daemon.json и не сбрасывает ли nftables.service правила Docker"
        )

    def _require_ready(self) -> AppConfig:
        config = self.store.load()
        if not config.first_run_complete or not config.wildcard_domain:
            raise ProxyCLIError("мастер ещё не завершён", fix="proxycli wizard --help")
        return config

    def _guard_upstream(
        self,
        origin: str,
        *,
        trust_private: bool,
        probe: bool,
        inactive: bool = False,
    ) -> tuple[str, bool]:
        """Return a warning and whether the upstream probe succeeded.

        The second value is False when the route is being saved without a
        successful reachability check. The caller must still keep that route:
        a failed DNS, TCP, or TLS probe is not a reason to roll it back.
        """
        if upstream_is_forbidden(origin):
            raise ValidationError(
                "апстрим на loopback, link-local или metadata запрещён",
                fix="эти адреса нельзя использовать даже с --trust-private",
            )
        if upstream_is_private_literal(origin) and not trust_private:
            raise ValidationError(
                "частный или служебный upstream запрещён без явного подтверждения",
                fix="повторите с --trust-private, если это ваш сервер",
            )
        if not probe or self.offline() or self._skip_probes():
            if inactive:
                return (
                    "Маршрут сохранён без успешной проверки upstream. "
                    "Caddy будет пересылать запросы. Успех доставки не подтверждён.",
                    False,
                )
            return ("проверка upstream пропущена, успех не заявляется", True)
        report = probe_upstream(origin, timeout=5, trust_private=trust_private)
        if report.ok:
            return ("", True)
        failed = report.failed()
        if failed is not None and failed.layer == "policy":
            raise ProbeError(report.summary(), layer="policy", fix=failed.fix)
        if not inactive:
            raise ProbeError(
                report.summary(),
                layer=failed.layer if failed else "upstream",
                fix=failed.fix if failed else "повторите с --inactive, чтобы сохранить маршрут неактивным",
            )
        return (
            f"Предупреждение: {report.summary()}. Маршрут сохранён. "
            "Caddy будет пересылать запросы. Успех доставки не подтверждён.",
            False,
        )

    def _rollback(self, snap: str, original: Exception, *, reason: str = "") -> None:
        try:
            self.backup.restore(snap)
        except Exception as exc:
            raise RollbackError(
                f"{original}. Откат файлов не удался: {exc}",
                fix=f"proxycli backup restore --id {snap}",
            ) from original
        if self._proxy_restarted and not self.offline():
            self._proxy_restarted = False
            try:
                self.render()
                self._recreate_proxy()
            except Exception as exc:
                note = f"Контейнер 3proxy не перечитан после отката: {exc}"
                if isinstance(original, ProxyCLIError):
                    original.message = f"{original.message} {note}"
                else:
                    raise RollbackError(
                        f"{original}. {note}",
                        fix=f"proxycli backup restore --id {snap}",
                    ) from original
        if isinstance(original, ProxyCLIError) and snap not in original.message:
            restored = (
                f"Файлы возвращены из копии {snap}; повторное восстановление не обязательно."
            )
            if reason == "wizard" and "Домен не сохранён" not in original.message:
                original.message = f"Домен не сохранён. {original.message} {restored}"
            else:
                original.message = f"{original.message} {restored}"
            if original.fix.startswith("proxycli backup restore"):
                original.fix = ""

    def _write_runtime(self, caddy: str, proxy: str, compose: str) -> bool:
        """Write runtime files; return True when 3proxy.cfg content changed.

        An unchanged 3proxy.cfg keeps its mtime so it can be compared with the
        container start time.
        """
        self.layout.ensure_dirs()
        atomic_write(self.layout.caddyfile, caddy, 0o644)
        cfg = self.layout.proxy_cfg
        previous = cfg.read_text(encoding="utf-8") if cfg.exists() else None
        if previous != proxy:
            atomic_write(cfg, proxy, 0o600)
        else:
            chmod(cfg, 0o600)
        atomic_write(self.layout.compose_file, compose, 0o644)
        atomic_write(self.layout.dockerfile, render_dockerfile(), 0o644)
        atomic_write(self.layout.entrypoint, ENTRYPOINT, 0o755)
        return previous != proxy

    def _docker_validate_and_reload(self) -> list[str]:
        config = self.store.load()
        image = CADDY_DNS_IMAGE if config.tls.mode == "dns" and config.tls.dns_plugin_ready else CADDY_IMAGE
        caddyfile = self.layout.caddyfile.resolve().as_posix()
        validate = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{caddyfile}:/etc/caddy/Caddyfile:ro",
            image,
            "caddy",
            "validate",
            "--config",
            "/etc/caddy/Caddyfile",
            "--adapter",
            "caddyfile",
        ]
        require_ok(self.runner(validate, timeout=90), validate)
        up = self._compose("up", "-d", "--remove-orphans")
        require_ok(self.runner(up, timeout=180), up)
        reload = self._compose(
            "exec",
            "-T",
            "caddy",
            "caddy",
            "reload",
            "--config",
            "/etc/caddy/Caddyfile",
            "--adapter",
            "caddyfile",
            "--address",
            CADDY_ADMIN,
        )
        reloaded = self.runner(reload, timeout=60)
        if reloaded.ok:
            return []
        if _admin_not_listening(reloaded):
            recreate = self._compose(
                "up",
                "-d",
                "--force-recreate",
                "--no-deps",
                "--remove-orphans",
                "caddy",
            )
            require_ok(self.runner(recreate, timeout=180), recreate)
            state = self.container_state(CADDY_CONTAINER)
            if state != "running":
                raise ProxyCLIError(
                    "контейнер Caddy не запущен после docker compose up -d "
                    f"(состояние: {state})",
                    fix="docker inspect proxycli-caddy",
                )
            return [
                "Admin API Caddy не принимал подключения на 127.0.0.1:2019, "
                "reload не засчитан. Контейнер перезапущен через docker compose up -d "
                "с проверенным Caddyfile. Успех TLS не заявляется."
            ]
        require_ok(reloaded, reload)
        return []

    def _recreate_proxy(self) -> None:
        config = self.store.load()
        if not (_active(config.socks) or _active(config.http)):
            return
        if self.offline():
            return
        self._proxy_restarted = True
        argv = self._compose("up", "-d", "--force-recreate", "--no-deps", "proxy3")
        require_ok(self.runner(argv, timeout=180), argv)
        state = self.container_state(PROXY_CONTAINER)
        if state != "running":
            raise ProxyCLIError(
                f"контейнер 3proxy не запущен после перезапуска (состояние: {state})",
                fix="docker inspect proxycli-3proxy",
            )

    def _proxy_needs_recreate(self) -> bool:
        """3proxy.cfg is a single-file bind mount: an atomic rename is invisible
        to the running container, so any newer file needs a recreate."""
        stale = self.proxy_config_stale()
        return self._proxy_cfg_changed if stale is None else stale

    def proxy_config_stale(self) -> bool | None:
        """True if 3proxy.cfg is newer than the running container; None if unknown."""
        if self.offline() or not self.layout.proxy_cfg.exists():
            return None
        result = self.runner(
            ["docker", "inspect", "-f", "{{.State.StartedAt}}", PROXY_CONTAINER],
            timeout=8,
        )
        started = _docker_time(result.stdout) if result.ok else None
        if started is None:
            return None
        return self.layout.proxy_cfg.stat().st_mtime > started

    def _compose(self, *args: str) -> list[str]:
        return [
            "docker",
            "compose",
            "-f",
            str(self.layout.compose_file),
            "--project-directory",
            str(self.layout.deploy_dir),
            *args,
        ]

    def _fail_step(self) -> str:
        if isinstance(self.runner, OfflineRunner):
            return self.runner.fail_step
        return os.environ.get("PROXYCLI_FAIL_STEP", "")

    def _skip_probes(self) -> bool:
        return os.environ.get("PROXYCLI_SKIP_PROBES") == "1"

    def container_state(self, name: str) -> str:
        if self.offline():
            return "не проверено (offline)"
        result = self.runner(
            ["docker", "inspect", "-f", "{{.State.Status}}", name],
            timeout=8,
        )
        if not result.ok:
            return "не запущен"
        return result.stdout.strip() or "неизвестно"

    def restart_policy(self, name: str) -> str:
        if self.offline():
            return "не проверено (offline)"
        result: ProcResult = self.runner(
            ["docker", "inspect", "-f", "{{.HostConfig.RestartPolicy.Name}}", name],
            timeout=8,
        )
        if not result.ok:
            return "неизвестно"
        return result.stdout.strip() or "неизвестно"


def _admin_not_listening(result: ProcResult) -> bool:
    text = f"{result.stdout}\n{result.stderr}".lower()
    if "connection refused" in text or "actively refused" in text:
        return True
    if "is not running" in text or "no such container" in text:
        return True
    return "i/o timeout" in text or "context deadline exceeded" in text


def _docker_time(text: str) -> float | None:
    """Parse docker StartedAt (RFC 3339 with nanoseconds) into a Unix timestamp."""
    value = text.strip()
    if not value or value.startswith("0001-"):
        return None
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    if "." in value:
        head, rest = value.split(".", 1)
        digits = "".join(itertools.takewhile(str.isdigit, rest))
        value = f"{head}.{digits[:6].ljust(6, '0')}{rest[len(digits):]}"
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return None


def _kind(kind: str) -> str:
    if kind == "socks":
        return "socks"
    if kind == "http":
        return "http"
    raise ValidationError("тип прокси: socks или http")

