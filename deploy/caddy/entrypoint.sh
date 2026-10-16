#!/bin/sh
set -eu
if [ -f /run/secrets/cloudflare_token ]; then
  IFS= read -r CLOUDFLARE_API_TOKEN < /run/secrets/cloudflare_token || exit 1
  export CLOUDFLARE_API_TOKEN
fi
# Official image has no ENTRYPOINT and a CMD of `caddy …`. This wrapper
# accepts both `caddy validate` and a bare subcommand such as `run`.
if [ "${1:-}" = "caddy" ]; then
  exec "$@"
fi
exec caddy "$@"
