from __future__ import annotations

import ipaddress
from ipaddress import IPv4Address, IPv6Address

BLOCKED_HOSTS = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata",
        "metadata.google.internal",
        "metadata.google.com",
        "instance-data",
    }
)

BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".localdomain")

# Destination networks that a public forward proxy must not reach.
BLOCKED_NETS = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/3"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
)

METADATA_IPS = frozenset({"169.254.169.254", "fd00:ec2::254"})


def parse_ip(value: str) -> IPv4Address | IPv6Address:
    return ipaddress.ip_address(value)


def is_blocked_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if str(address) in METADATA_IPS:
        return True
    if (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        return True
    return any(address in network for network in BLOCKED_NETS)


def is_public_ipv4(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return isinstance(address, IPv4Address) and address.is_global


def is_blocked_host(host: str) -> bool:
    name = host.strip().lower().rstrip(".")
    if name in BLOCKED_HOSTS:
        return True
    if any(name.endswith(suffix) for suffix in BLOCKED_SUFFIXES):
        return True
    if name.startswith("["):
        inner = name[1:].split("]", 1)[0]
        return is_blocked_ip(inner)
    return is_blocked_ip(name)


def _host_name(host: str) -> str:
    return host.strip().lower().rstrip(".")


def _host_address(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(_host_name(host))
    except ValueError:
        return None


def is_loopback_host(host: str) -> bool:
    name = _host_name(host)
    if name in {"localhost", "localhost.localdomain"} or name.endswith(".localhost"):
        return True
    address = _host_address(name)
    return address is not None and address.is_loopback


def is_link_local_host(host: str) -> bool:
    address = _host_address(host)
    return address is not None and address.is_link_local


def is_metadata_host(host: str) -> bool:
    name = _host_name(host)
    if name in {"metadata", "metadata.google.internal", "metadata.google.com", "instance-data"}:
        return True
    address = _host_address(name)
    return address is not None and str(address) in METADATA_IPS


def is_forbidden_upstream_host(host: str) -> bool:
    """Loopback, link-local, and cloud metadata are never a webhook upstream."""
    return is_loopback_host(host) or is_link_local_host(host) or is_metadata_host(host)
