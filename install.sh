#!/usr/bin/env bash
# ProxyCLI installer for Ubuntu 24.04/26.04 and Debian 13.
# Re-running keeps /etc/proxycli/config.json and does not touch SSH.
# -E/errtrace: without it a failing command inside a function exits under set -e
# and the ERR trap never runs, so the installer stops with no message.
set -eEuo pipefail

PROXYCLI_VERSION="1.0.0"
INSTALL_DIR="/opt/proxycli"
REPO_URL="https://github.com/driverm35/proxycli.git"
CADDY_IMAGE="caddy:2.11.7"
THREEPROXY_IMAGE="3proxy/3proxy:0.9.9.1"
DOCKER_CE_VERSION="29.8.2"
INSTALL_LOG="/var/log/proxycli/install.log"

err_status=0
err_cmd=""
err_line=0

die() {
  printf 'Ошибка: %s\n' "$*" >&2
  printf 'Диагностика: cat %s; journalctl -u docker.service --no-pager -n 50; повторный запуск с трассировкой: bash -x install.sh\n' "${INSTALL_LOG}" >&2
  exit 1
}

on_err() {
  local status="${err_status:-1}"
  local line="${err_line:-0}"
  local cmd="${err_cmd:-неизвестная команда}"
  trap - ERR
  if [[ "${status}" -eq 0 ]]; then
    status=1
  fi
  printf 'Ошибка установки ProxyCLI: команда завершилась с кодом %s.\n' "${status}" >&2
  printf 'Команда: %s\n' "${cmd}" >&2
  printf 'Строка: %s\n' "${line}" >&2
  printf 'Диагностика: cat %s; journalctl -u docker.service --no-pager -n 50; повторный запуск с трассировкой: bash -x install.sh\n' "${INSTALL_LOG}" >&2
  exit "${status}"
}

# Capture BASH_COMMAND here. Inside on_err it may already be the trap body.
trap 'err_status=$?; err_cmd="$BASH_COMMAND"; err_line="${BASH_LINENO[0]:-${LINENO}}"; trap - ERR; on_err' ERR

setup_logging() {
  local log_dir="/var/log/proxycli"
  if [[ "${PROXYCLI_INSTALL_LOG_READY:-}" == "1" ]]; then
    return 0
  fi
  install -d -m 0750 "${log_dir}"
  touch "${INSTALL_LOG}"
  chmod 0640 "${INSTALL_LOG}"
  exec > >(tee -a "${INSTALL_LOG}") 2>&1
  PROXYCLI_INSTALL_LOG_READY=1
  printf '---- proxycli install %s ----\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ || true)"
}

check_os() {
  local id=""
  local version=""
  if [[ -n "${PROXYCLI_ASSUME_OS:-}" ]]; then
    id="${PROXYCLI_ASSUME_OS%%-*}"
    version="${PROXYCLI_ASSUME_OS#*-}"
  else
    if [[ ! -r /etc/os-release ]]; then
      echo "ОС не поддерживается: нет /etc/os-release." >&2
      return 1
    fi
    ID=""
    VERSION_ID=""
    # shellcheck disable=SC1091
    . /etc/os-release
    id="${ID}"
    version="${VERSION_ID}"
  fi
  local ok=0
  if [[ "${id}" == "ubuntu" && ( "${version}" == "24.04" || "${version}" == "26.04" ) ]]; then
    ok=1
  fi
  case "${id}-${version}" in
    debian-13 | debian-13.*) ok=1 ;;
    *) ;;
  esac
  if [[ "${ok}" -ne 1 ]]; then
    echo "ОС ${id} ${version} не поддерживается. Нужны Ubuntu 24.04/26.04 или Debian 13." >&2
    return 1
  fi
}

check_arch() {
  local machine="${PROXYCLI_ASSUME_ARCH:-}"
  if [[ -z "${machine}" ]]; then
    machine="$(uname -m)"
  fi
  case "${machine}" in
    x86_64 | amd64 | aarch64 | arm64) ;;
    *)
      echo "Архитектура ${machine} не поддерживается. Нужна amd64 или arm64." >&2
      return 1
      ;;
  esac
}

check_internet() {
  if ! curl -fsSL --max-time 20 -o /dev/null "https://github.com/driverm35/proxycli"; then
    die "Нет доступа к GitHub. Проверка: curl -I --max-time 20 https://github.com/driverm35/proxycli"
  fi
}

assert_port_free() {
  local port="$1"
  local mock="${PROXYCLI_MOCK_LISTENERS:-}"
  if [[ -n "${mock}" ]]; then
    local mock_port
    local mock_proc
    mock_port="${mock%% *}"
    mock_proc="${mock#* }"
    if [[ "${mock_port}" == "${port}" ]]; then
      case "${mock_proc}" in
        docker-proxy | caddy) return 0 ;;
        *)
          echo "Порт ${port} занят процессом ${mock_proc}." >&2
          return 1
          ;;
      esac
    fi
    return 0
  fi
  if ! command -v ss >/dev/null 2>&1; then
    echo "ss не найден, порт ${port} не проверен."
    return 0
  fi
  local dump
  dump="$(ss -ltnp "sport = :${port}" || true)"
  if [[ "${dump}" != *"LISTEN"* ]]; then
    return 0
  fi
  if [[ "${dump}" == *"docker-proxy"* || "${dump}" == *"caddy"* ]]; then
    return 0
  fi
  echo "Порт ${port} занят чужим процессом. Диагностика: ss -ltnp 'sport = :${port}'" >&2
  return 1
}

require_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    die "Нужны права root. Запуск: curl -fsSL https://raw.githubusercontent.com/driverm35/proxycli/main/install.sh | sudo bash"
  fi
}

# Prints 1 when haystack contains token as its own version, not as a prefix of 29.8.20.
docker_version_matches() {
  local haystack="$1"
  local token="$2"
  local rest="${haystack}"
  local head=""
  local after=""
  local before_char=""
  local after_char=""
  if [[ -z "${token}" ]]; then
    printf '0\n'
    return 0
  fi
  while [[ "${rest}" == *"${token}"* ]]; do
    head="${rest%%"${token}"*}"
    after="${rest#*"${token}"}"
    before_char=""
    after_char=""
    if [[ -n "${head}" ]]; then
      before_char="${head#"${head%?}"}"
    fi
    if [[ -n "${after}" ]]; then
      after_char="${after%"${after#?}"}"
    fi
    case "${before_char}" in
      "" | [!0-9.])
        case "${after_char}" in
          "" | [!0-9])
            printf '1\n'
            return 0
            ;;
        esac
        ;;
    esac
    if [[ -z "${after}" ]]; then
      printf '0\n'
      return 0
    fi
    rest="${after}"
  done
  printf '0\n'
}

# madison lists the highest version first. Stdout is "pinned <ver>", "newest <ver>", or "distro".
choose_docker_source() {
  local madison=""
  local line=""
  local ver=""
  local newest=""
  local pinned=""
  local matched=""
  madison="$(apt-cache madison docker-ce 2>/dev/null || true)"
  while IFS= read -r line || [[ -n "${line}" ]]; do
    if [[ -z "${line}" ]]; then
      continue
    fi
    ver="${line#*|}"
    ver="${ver%%|*}"
    ver="${ver#"${ver%%[![:space:]]*}"}"
    ver="${ver%"${ver##*[![:space:]]}"}"
    if [[ -z "${ver}" || "${ver}" == "|" ]]; then
      continue
    fi
    if [[ -z "${newest}" ]]; then
      newest="${ver}"
    fi
    if [[ -z "${pinned}" ]]; then
      matched="$(docker_version_matches "${ver}" "${DOCKER_CE_VERSION}")"
      if [[ "${matched}" == "1" ]]; then
        pinned="${ver}"
      fi
    fi
  done <<< "${madison}"
  if [[ -n "${pinned}" ]]; then
    printf 'pinned %s\n' "${pinned}"
    return 0
  fi
  if [[ -n "${newest}" ]]; then
    printf 'Предупреждение: docker-ce %s нет в репозитории этого выпуска. Будет установлена новейшая версия %s.\n' \
      "${DOCKER_CE_VERSION}" "${newest}" >&2
    printf 'newest %s\n' "${newest}"
    return 0
  fi
  printf 'Предупреждение: в download.docker.com нет пакетов docker-ce для этого выпуска. Будут пакеты дистрибутива docker.io и docker-compose-v2.\n' >&2
  printf 'distro\n'
}

docker_is_working() {
  if ! command -v docker >/dev/null 2>&1; then
    printf 'no\n'
    return 0
  fi
  if ! docker info >/dev/null 2>&1; then
    printf 'no\n'
    return 0
  fi
  if ! docker compose version >/dev/null 2>&1; then
    printf 'no\n'
    return 0
  fi
  printf 'yes\n'
}

print_installed_docker_version() {
  local pkg=""
  local ver=""
  for pkg in docker-ce docker.io; do
    ver="$(dpkg-query -W -f '${Version}' "${pkg}" 2>/dev/null || true)"
    if [[ -n "${ver}" ]]; then
      printf 'Установлена версия %s %s\n' "${pkg}" "${ver}"
      return 0
    fi
  done
  printf 'Предупреждение: версия пакета Docker не прочитана через dpkg.\n' >&2
}

install_distro_docker() {
  local compose_pkg=""
  if apt-cache show docker-compose-v2 >/dev/null 2>&1; then
    compose_pkg="docker-compose-v2"
  elif apt-cache show docker-compose-plugin >/dev/null 2>&1; then
    compose_pkg="docker-compose-plugin"
  fi
  if [[ -n "${compose_pkg}" ]]; then
    printf 'Ставлю пакеты дистрибутива: docker.io %s\n' "${compose_pkg}"
    apt-get install -y docker.io "${compose_pkg}"
  else
    printf 'Предупреждение: в дистрибутиве нет docker-compose-v2 и docker-compose-plugin. Ставлю только docker.io.\n' >&2
    apt-get install -y docker.io
  fi
}

install_docker_packages() {
  local codename=""
  local id_name=""
  local arch=""
  local choice=""
  local version=""
  local docker_state=""
  docker_state="$(docker_is_working)"
  if [[ "${docker_state}" == "yes" ]]; then
    echo "Docker уже установлен и работает, установка Docker пропущена."
    print_installed_docker_version
    return 0
  fi
  # shellcheck disable=SC1091
  . /etc/os-release
  id_name="${ID:-}"
  codename="${VERSION_CODENAME:-}"
  if [[ -z "${id_name}" || -z "${codename}" ]]; then
    die "В /etc/os-release нет ID или VERSION_CODENAME."
  fi
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/${id_name}/gpg" -o /etc/apt/keyrings/docker.asc \
    || die "не скачать ключ Docker. Диагностика: curl -I https://download.docker.com/linux/${id_name}/gpg"
  chmod 0644 /etc/apt/keyrings/docker.asc
  arch="$(dpkg --print-architecture)"
  cat > /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/${id_name}
Suites: ${codename}
Components: stable
Architectures: ${arch}
Signed-By: /etc/apt/keyrings/docker.asc
EOF
  if ! apt-get update; then
    printf 'Предупреждение: apt-get update не принял репозиторий Docker для %s. Ставлю пакеты дистрибутива.\n' "${codename}" >&2
    rm -f /etc/apt/sources.list.d/docker.sources
    apt-get update || die "apt-get update не обновил списки пакетов дистрибутива после отключения репозитория Docker."
    install_distro_docker
    print_installed_docker_version
    return 0
  fi
  choice="$(choose_docker_source)"
  case "${choice}" in
    pinned\ *)
      version="${choice#pinned }"
      printf 'Ставлю закреплённый Docker CE %s (%s).\n' "${version}" "${DOCKER_CE_VERSION}"
      apt-get install -y "docker-ce=${version}" "docker-ce-cli=${version}" containerd.io docker-buildx-plugin docker-compose-plugin
      if ! apt-mark hold docker-ce docker-ce-cli; then
        printf 'Предупреждение: apt-mark hold не закрепил docker-ce %s.\n' "${version}" >&2
      fi
      ;;
    newest\ *)
      version="${choice#newest }"
      printf 'Ставлю новейший Docker CE из download.docker.com: %s.\n' "${version}"
      if ! apt-get install -y "docker-ce=${version}" "docker-ce-cli=${version}" containerd.io docker-buildx-plugin docker-compose-plugin; then
        printf 'Предупреждение: пакеты версии %s не установились. Ставлю новейшие пакеты Docker без пина.\n' "${version}" >&2
        apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
      fi
      ;;
    distro)
      install_distro_docker
      ;;
    *)
      die "не удалось выбрать способ установки Docker (${choice:-пусто}). Диагностика: apt-cache madison docker-ce"
      ;;
  esac
  print_installed_docker_version
}

install_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y python3 python3-venv python3-pip ca-certificates curl git nftables iproute2
  install_docker_packages
}

enable_docker() {
  local server=""
  local compose=""
  if ! command -v systemctl >/dev/null 2>&1; then
    die "systemd не найден, автозапуск Docker невозможен."
  fi
  systemctl enable --now docker.service \
    || die "не удалось включить docker.service. Диагностика: systemctl status docker.service --no-pager; journalctl -u docker.service --no-pager -n 50"
  if ! docker info >/dev/null; then
    die "docker info не выполнен. Диагностика: journalctl -u docker.service --no-pager -n 80"
  fi
  if ! docker compose version >/dev/null; then
    die "docker compose version не выполнен. Диагностика: docker compose version"
  fi
  server="$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)"
  compose="$(docker compose version 2>/dev/null || true)"
  printf 'Docker проверен: сервер %s\n' "${server:-неизвестен}"
  printf 'Compose проверен: %s\n' "${compose:-нет вывода}"
}

install_tree() {
  if [[ -e "${INSTALL_DIR}" && ! -d "${INSTALL_DIR}/.git" ]]; then
    die "${INSTALL_DIR} уже существует и это не репозиторий ProxyCLI. Каталог не удалён."
  fi
  if [[ ! -d "${INSTALL_DIR}/.git" ]]; then
    git clone --depth 1 --branch main "${REPO_URL}" "${INSTALL_DIR}"
  else
    git -C "${INSTALL_DIR}" fetch --depth 1 origin main
    git -C "${INSTALL_DIR}" checkout main
    git -C "${INSTALL_DIR}" pull --ff-only origin main
  fi
  python3 -m venv "${INSTALL_DIR}/.venv"
  "${INSTALL_DIR}/.venv/bin/pip" install --upgrade pip
  "${INSTALL_DIR}/.venv/bin/pip" install "${INSTALL_DIR}"
  ln -sfn "${INSTALL_DIR}/.venv/bin/proxycli" /usr/local/bin/proxycli
}

install_dirs() {
  install -d -m 0750 /etc/proxycli /var/log/proxycli /var/lib/proxycli/backups /var/lib/proxycli/deploy
  if [[ -f /etc/proxycli/config.json ]]; then
    echo "Существующий /etc/proxycli/config.json сохранён."
  fi
}

install_runtime_files() {
  if [[ -f /var/lib/proxycli/deploy/compose.yaml ]]; then
    echo "Существующий /var/lib/proxycli/deploy/compose.yaml сохранён."
    return 0
  fi
  install -d -m 0750 /var/lib/proxycli/deploy/caddy /var/lib/proxycli/deploy/3proxy
  install -m 0640 "${INSTALL_DIR}/deploy/compose.yaml" /var/lib/proxycli/deploy/compose.yaml
  install -m 0640 "${INSTALL_DIR}/deploy/caddy/Caddyfile" /var/lib/proxycli/deploy/caddy/Caddyfile
  install -m 0640 "${INSTALL_DIR}/deploy/caddy/Dockerfile" /var/lib/proxycli/deploy/caddy/Dockerfile
  install -m 0750 "${INSTALL_DIR}/deploy/caddy/entrypoint.sh" /var/lib/proxycli/deploy/caddy/entrypoint.sh
  install -m 0640 "${INSTALL_DIR}/deploy/3proxy/3proxy.cfg" /var/lib/proxycli/deploy/3proxy/3proxy.cfg
}

install_unit() {
  if [[ -f "${INSTALL_DIR}/deploy/systemd/proxycli.service" ]]; then
    install -m 0644 "${INSTALL_DIR}/deploy/systemd/proxycli.service" /etc/systemd/system/proxycli.service
    systemctl daemon-reload
    systemctl enable proxycli.service
  fi
}

report() {
  echo "---- ProxyCLI ${PROXYCLI_VERSION} ----"
  echo "Caddy ${CADDY_IMAGE}"
  echo "3proxy ${THREEPROXY_IMAGE}"
  proxycli version || true
  if proxycli doctor; then
    echo "doctor: критичных ошибок нет"
  else
    echo "doctor: есть замечания. До proxycli wizard это ожидаемо."
  fi
  echo "Повторный запуск не удаляет /etc/proxycli/config.json и не меняет SSH."
}

launch_menu() {
  if [[ -t 0 && -t 1 ]]; then
    exec proxycli
  fi
  echo "Установка завершена. Интерактивное меню: sudo proxycli"
}

main() {
  local mode="${1:-}"
  if [[ "${mode}" == "--dry-run" || "${mode}" == "--preflight" ]]; then
    check_os
    check_arch
    echo "dry-run: установка не выполняется"
    echo "Docker CE ${DOCKER_CE_VERSION}"
    echo "Caddy ${CADDY_IMAGE}"
    echo "3proxy ${THREEPROXY_IMAGE}"
    exit 0
  fi
  require_root
  setup_logging
  check_os
  check_arch
  check_internet
  install_packages
  assert_port_free 80
  assert_port_free 443
  enable_docker
  install_tree
  install_dirs
  install_runtime_files
  install_unit
  report
  launch_menu
}

# `curl | bash` leaves BASH_SOURCE unset; ${BASH_SOURCE[0]} aborts under set -u.
# An empty source means this process is the installer. A different path means it was sourced.
if [[ -z "${BASH_SOURCE[0]:-}" || "${BASH_SOURCE[0]:-}" == "${0}" ]]; then
  main "$@"
fi
