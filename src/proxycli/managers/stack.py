from __future__ import annotations

import os
import uuid

from proxycli.constants import CADDY_DNS_IMAGE, CADDY_DNS_MODULE, CADDY_IMAGE
from proxycli.errors import ProbeError, ProxyCLIError, RollbackError, ValidationError
from proxycli.managers.backup import BackupManager
from proxycli.models.config import AppConfig, ProxyUser, Route
from proxycli.services.caddyfile import (
    WILDCARD_FALLBACK,
    assert_caddyfile_contains_routes,
    render_caddyfile,
)
from proxycli.services.compose import ENTRYPOINT, render_compose, render_dockerfile
from proxycli.services.events import EventLog
from proxycli.services.probes import check_name_dns, probe_public_https, probe_upstream
from proxycli.services.proxy3cfg import render_3proxy
from proxycli.services.store import Store, generate_password
from proxycli.utils.files import atomic_write
from proxycli.utils.paths import PathLayout
from proxycli.utils.proc import OfflineRunner, ProcResult, Runner, make_runner, require_ok
from proxycli.utils.validation import (
    secret_ref,
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

    def offline(self) -> bool:
        return isinstance(self.runner, OfflineRunner) or os.environ.get("PROXYCLI_OFFLINE") == "1"

    def render(self) -> list[str]:
        config = self.store.load()
        secrets = self.store.load_secrets()
        caddy, warnings = render_caddyfile(config)
        proxy = render_3proxy(config, secrets)
        compose = render_compose(config, self.layout.token_file)
        assert_caddyfile_contains_routes(caddy, config)
        self._write_runtime(caddy, proxy, compose)
        return warnings

    def reload(
        self,
        *,
        probe_hosts: list[str] | None = None,
        probe: bool = True,
        simulate_failure: bool = True,
    ) -> list[str]:
        warnings = self.render()
        if simulate_failure and self._fail_step() == "reload":
            raise ProxyCLIError("симулированный сбой reload", fix="proxycli backup list")
        if self.offline():
            warnings.append("offline: Docker и публичный TLS не проверялись, успех не заявляется")
            return warnings
        self._docker_validate_and_reload()
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
    ) -> list[str]:
        snap = self.backup.create(reason)
        try:
            mutate()
            return self.reload(probe_hosts=probe_hosts, probe=probe)
        except Exception as exc:
            self._rollback(snap, exc)
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
                raise ProbeError(detail, layer="dns", fix="создайте A-запись или передайте --accept-dns")
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
        listed = self.runner(["docker", "run", "--rm", CADDY_DNS_IMAGE, "list-modules"], timeout=90)
        if listed.ok and CADDY_DNS_MODULE in listed.stdout:
            return True, "модуль dns.providers.cloudflare подтверждён командой list-modules"
        return False, "list-modules не подтвердил dns.providers.cloudflare; wildcard TLS не заявляется"

    def add_route(self, subdomain: str, upstream: str, *, trust_private: bool, probe: bool) -> list[str]:
        sub = validate_subdomain(subdomain)
        origin = validate_upstream(upstream)
        config = self._require_ready()
        if config.route(sub):
            raise ValidationError(f"маршрут {sub} уже есть")
        warnings = [self._guard_upstream(origin, trust_private=trust_private, probe=probe)]
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

        warnings.extend(self.transaction("route-add", mutate, probe_hosts=[host], probe=probe))
        self.events.write("route.add", subdomain=sub, upstream=origin, trust_private=trust_private)
        return [item for item in warnings if item]

    def edit_route(self, subdomain: str, upstream: str, *, trust_private: bool, probe: bool) -> list[str]:
        sub = validate_subdomain(subdomain)
        origin = validate_upstream(upstream)
        config = self._require_ready()
        if config.route(sub) is None:
            raise ValidationError(f"маршрут {sub} не найден")
        warnings = [self._guard_upstream(origin, trust_private=trust_private, probe=probe)]
        host = config.hostname(sub)

        def mutate() -> None:
            current = self.store.load()
            route = current.route(sub)
            if route is None:
                raise ValidationError(f"маршрут {sub} не найден")
            route.upstream = origin
            route.trust_private = trust_private
            self.store.save(current)

        warnings.extend(self.transaction("route-edit", mutate, probe_hosts=[host], probe=probe))
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

    def _require_ready(self) -> AppConfig:
        config = self.store.load()
        if not config.first_run_complete or not config.wildcard_domain:
            raise ProxyCLIError("мастер ещё не завершён", fix="proxycli wizard --help")
        return config

    def _guard_upstream(self, origin: str, *, trust_private: bool, probe: bool) -> str:
        if upstream_is_private_literal(origin) and not trust_private:
            raise ValidationError(
                "частный или служебный upstream запрещён без явного подтверждения",
                fix="повторите с --trust-private, если это ваш сервер",
            )
        if not probe or self.offline() or self._skip_probes():
            return "проверка upstream пропущена, успех не заявляется"
        report = probe_upstream(origin, timeout=5, trust_private=trust_private)
        if not report.ok:
            failed = report.failed()
            raise ProbeError(
                report.summary(),
                layer=failed.layer if failed else "upstream",
                fix=failed.fix if failed else "",
            )
        return ""

    def _rollback(self, snap: str, original: Exception) -> None:
        try:
            self.backup.restore(snap)
            self.reload(probe=False, simulate_failure=False)
        except Exception as exc:
            raise RollbackError(
                f"откат не удался: {exc}",
                fix=f"proxycli backup restore --id {snap}",
            ) from original

    def _write_runtime(self, caddy: str, proxy: str, compose: str) -> None:
        self.layout.ensure_dirs()
        atomic_write(self.layout.caddyfile, caddy, 0o644)
        atomic_write(self.layout.proxy_cfg, proxy, 0o600)
        atomic_write(self.layout.compose_file, compose, 0o644)
        atomic_write(self.layout.dockerfile, render_dockerfile(), 0o644)
        atomic_write(self.layout.entrypoint, ENTRYPOINT, 0o755)

    def _docker_validate_and_reload(self) -> None:
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
            "validate",
            "--config",
            "/etc/caddy/Caddyfile",
            "--adapter",
            "caddyfile",
        ]
        require_ok(self.runner(validate, timeout=90), validate)
        compose = [
            "docker",
            "compose",
            "-f",
            str(self.layout.compose_file),
            "--project-directory",
            str(self.layout.deploy_dir),
            "up",
            "-d",
            "--remove-orphans",
        ]
        require_ok(self.runner(compose, timeout=180), compose)
        reload = [
            "docker",
            "compose",
            "-f",
            str(self.layout.compose_file),
            "--project-directory",
            str(self.layout.deploy_dir),
            "exec",
            "-T",
            "caddy",
            "caddy",
            "reload",
            "--config",
            "/etc/caddy/Caddyfile",
            "--adapter",
            "caddyfile",
        ]
        require_ok(self.runner(reload, timeout=60), reload)

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


def _kind(kind: str) -> str:
    if kind == "socks":
        return "socks"
    if kind == "http":
        return "http"
    raise ValidationError("тип прокси: socks или http")

