"""Pinned runtime versions. install.sh and the Docker assets must match these strings."""

from proxycli import __version__

APP_VERSION = __version__

CADDY_VERSION = "2.11.7"
CADDY_IMAGE = f"caddy:{CADDY_VERSION}"
CADDY_BUILDER_IMAGE = f"caddy:{CADDY_VERSION}-builder"
CADDY_DNS_IMAGE = f"proxycli-caddy:{CADDY_VERSION}-cf"
CADDY_DNS_MODULE = "dns.providers.cloudflare"
CADDY_DNS_PLUGIN = "github.com/caddy-dns/cloudflare@v0.2.4"

THREEPROXY_IMAGE = "3proxy/3proxy:0.9.9.1"

DOCKER_CE_VERSION = "29.8.2"
PIP_VERSION = "25.1.1"

NFT_COMMENT = "proxycli"
COMPOSE_PROJECT = "proxycli"
CADDY_CONTAINER = "proxycli-caddy"
PROXY_CONTAINER = "proxycli-3proxy"
CADDY_ADMIN = "127.0.0.1:2019"

DEFAULT_SOCKS_PORT = 1080
DEFAULT_HTTP_PORT = 3128
SSH_PORT = 22

GITHUB_REPO = "https://github.com/driverm35/proxycli.git"
GITHUB_TARBALL = "https://github.com/driverm35/proxycli/archive/refs/heads/main.tar.gz"

SECRET_MODE = 0o600
CONFIG_MODE = 0o640
BACKUP_DIR_MODE = 0o700
