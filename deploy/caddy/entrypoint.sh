#!/bin/sh
set -eu
if [ -f /run/secrets/cloudflare_token ]; then
  IFS= read -r CLOUDFLARE_API_TOKEN < /run/secrets/cloudflare_token || exit 1
  export CLOUDFLARE_API_TOKEN
fi
exec caddy "$@"
