#!/usr/bin/env bash
# Remove ProxyCLI. By default keeps config, secrets, backups and Docker volumes.
# Does not flush nftables and does not change SSH.
set -euo pipefail

PURGE=0
YES=0

log() {
  printf '%s\n' "$*"
}

die() {
  local reason="$1"
  local diag="${2:-}"
  printf 'Ошибка удаления: %s\n' "$reason" >&2
  if [[ -n "$diag" ]]; then
    printf 'Диагностика: %s\n' "$diag" >&2
  fi
  exit 1
}

usage() {
  cat <<'EOF'
Использование: sudo bash uninstall.sh [--purge] [--yes]

Без --purge сохраняет /etc/proxycli, журналы и /var/lib/proxycli.
--purge удаляет конфигурацию, секреты, резервные копии и тома Caddy.
Нужен --yes, если нет терминала.
Firewall: удаляются только правила с комментарием proxycli-*. Flush не выполняется.
EOF
}

parse_args() {
  local arg
  for arg in "$@"; do
    case "$arg" in
      --purge) PURGE=1 ;;
      --yes) YES=1 ;;
      -h|--help) usage; exit 0 ;;
      *) die "неизвестный аргумент: ${arg}" "bash uninstall.sh --help" ;;
    esac
  done
}

check_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "нужны права root" "sudo bash uninstall.sh"
  fi
}

confirm_purge() {
  local answer=""
  if [[ "$PURGE" != "1" ]]; then
    return 0
  fi
  if [[ "$YES" == "1" ]]; then
    return 0
  fi
  # stdin is the script when piped, so the confirmation has to come from the terminal.
  if [[ -r /dev/tty ]] && read -r -p "Удалить конфигурацию, секреты и тома? [y/N] " answer </dev/tty; then
    if [[ "$answer" != "y" && "$answer" != "Y" ]]; then
      die "удаление данных отменено" "bash uninstall.sh --purge --yes"
    fi
    return 0
  fi
  die "purge без TTY требует --yes" "bash uninstall.sh --purge --yes"
}

rollback_firewall() {
  if [[ ! -x /usr/local/bin/proxycli ]]; then
    log "proxycli уже нет, правила firewall не трогаю автоматически"
    return 0
  fi
  if ! /usr/local/bin/proxycli firewall rollback; then
    log "Откат правил proxycli не выполнен. Общий firewall не сбрасывался."
    log "Диагностика: nft -a list ruleset"
  fi
}

stop_stack() {
  if [[ -f /etc/systemd/system/proxycli.service ]]; then
    systemctl disable --now proxycli.service || true
    rm -f /etc/systemd/system/proxycli.service
    systemctl daemon-reload || true
  fi
  if [[ -f /var/lib/proxycli/deploy/compose.yaml ]] && command -v docker >/dev/null 2>&1; then
    if [[ "$PURGE" == "1" ]]; then
      docker compose -f /var/lib/proxycli/deploy/compose.yaml --project-directory /var/lib/proxycli/deploy down -v \
        || log "compose down -v завершился с ошибкой; проверьте docker ps"
    else
      docker compose -f /var/lib/proxycli/deploy/compose.yaml --project-directory /var/lib/proxycli/deploy down \
        || log "compose down завершился с ошибкой; проверьте docker ps"
    fi
  fi
}

remove_app() {
  rm -f /usr/local/bin/proxycli
  rm -rf /opt/proxycli
  if [[ "$PURGE" == "1" ]]; then
    rm -rf /etc/proxycli /var/log/proxycli /var/lib/proxycli
    log "Данные ProxyCLI удалены"
  else
    log "Сохранены /etc/proxycli, /var/log/proxycli и /var/lib/proxycli"
  fi
}

main() {
  parse_args "$@"
  check_root
  confirm_purge
  rollback_firewall
  stop_stack
  remove_app
  log "ProxyCLI удалён"
}

# `curl | bash` leaves BASH_SOURCE unset; ${BASH_SOURCE[0]} aborts under set -u.
# An empty source means this process is the uninstaller. A different path means it was sourced.
if [[ -z "${BASH_SOURCE[0]:-}" || "${BASH_SOURCE[0]:-}" == "$0" ]]; then
  main "$@"
fi
