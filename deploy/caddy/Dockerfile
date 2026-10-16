ARG CADDY_VERSION=2.11.7
FROM caddy:${CADDY_VERSION}-builder AS builder
ARG CADDY_VERSION
ARG CF_PLUGIN=github.com/caddy-dns/cloudflare@v0.2.4
RUN xcaddy build "v${CADDY_VERSION}" --with "${CF_PLUGIN}"

FROM caddy:${CADDY_VERSION}
COPY entrypoint.sh /usr/local/bin/proxycli-entrypoint
RUN chmod +x /usr/local/bin/proxycli-entrypoint
ENTRYPOINT ["proxycli-entrypoint"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
