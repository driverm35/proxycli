from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

TlsMode = Literal["http", "dns"]


@dataclass
class TlsSettings:
    mode: TlsMode = "http"
    acme_email: str = ""
    dns_plugin_ready: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "acme_email": self.acme_email,
            "dns_plugin_ready": self.dns_plugin_ready,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TlsSettings:
        mode = data.get("mode", "http")
        if mode not in ("http", "dns"):
            raise ValueError(f"неизвестный режим TLS: {mode}")
        return cls(
            mode=mode,
            acme_email=str(data.get("acme_email", "")),
            dns_plugin_ready=bool(data.get("dns_plugin_ready", False)),
        )


@dataclass
class ProxyUser:
    username: str
    secret_ref: str

    def to_dict(self) -> dict[str, str]:
        return {"username": self.username, "secret_ref": self.secret_ref}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProxyUser:
        return cls(username=str(data["username"]), secret_ref=str(data["secret_ref"]))


@dataclass
class Listener:
    enabled: bool = False
    port: int = 1080
    allowlist: list[str] = field(default_factory=list)
    users: list[ProxyUser] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "port": self.port,
            "allowlist": list(self.allowlist),
            "users": [user.to_dict() for user in self.users],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], default_port: int) -> Listener:
        return cls(
            enabled=bool(data.get("enabled", False)),
            port=int(data.get("port", default_port)),
            allowlist=[str(item) for item in data.get("allowlist", [])],
            users=[ProxyUser.from_dict(item) for item in data.get("users", [])],
        )

    def user(self, username: str) -> ProxyUser | None:
        for item in self.users:
            if item.username == username:
                return item
        return None


@dataclass
class Route:
    subdomain: str
    upstream: str
    trust_private: bool = False
    enabled: bool = True
    id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "subdomain": self.subdomain,
            "upstream": self.upstream,
            "trust_private": self.trust_private,
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Route:
        return cls(
            id=str(data.get("id", "")),
            subdomain=str(data["subdomain"]),
            upstream=str(data["upstream"]),
            trust_private=bool(data.get("trust_private", False)),
            enabled=bool(data.get("enabled", True)),
        )


@dataclass
class AppConfig:
    version: int = 1
    public_ipv4: str = ""
    wildcard_domain: str = ""
    tls: TlsSettings = field(default_factory=TlsSettings)
    socks: Listener = field(default_factory=lambda: Listener(port=1080))
    http: Listener = field(default_factory=lambda: Listener(port=3128))
    routes: list[Route] = field(default_factory=list)
    firewall_managed: bool = False
    first_run_complete: bool = False
    dns_ok: bool | None = None
    dns_detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "public_ipv4": self.public_ipv4,
            "wildcard_domain": self.wildcard_domain,
            "tls": self.tls.to_dict(),
            "socks": self.socks.to_dict(),
            "http": self.http.to_dict(),
            "routes": [route.to_dict() for route in self.routes],
            "firewall_managed": self.firewall_managed,
            "first_run_complete": self.first_run_complete,
            "dns_ok": self.dns_ok,
            "dns_detail": self.dns_detail,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AppConfig:
        from proxycli.constants import DEFAULT_HTTP_PORT, DEFAULT_SOCKS_PORT

        return cls(
            version=int(data.get("version", 1)),
            public_ipv4=str(data.get("public_ipv4", "")),
            wildcard_domain=str(data.get("wildcard_domain", "")),
            tls=TlsSettings.from_dict(dict(data.get("tls") or {})),
            socks=Listener.from_dict(dict(data.get("socks") or {}), DEFAULT_SOCKS_PORT),
            http=Listener.from_dict(dict(data.get("http") or {}), DEFAULT_HTTP_PORT),
            routes=[Route.from_dict(item) for item in data.get("routes", [])],
            firewall_managed=bool(data.get("firewall_managed", False)),
            first_run_complete=bool(data.get("first_run_complete", False)),
            dns_ok=data.get("dns_ok", None),
            dns_detail=str(data.get("dns_detail", "")),
        )

    def route(self, subdomain: str) -> Route | None:
        for item in self.routes:
            if item.subdomain == subdomain:
                return item
        return None

    def hostname(self, subdomain: str) -> str:
        return f"{subdomain}.{self.wildcard_domain}"
