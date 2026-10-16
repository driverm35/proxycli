#!/usr/bin/env bash
# ProxyCLI installer for Ubuntu 24.04/26.04 and Debian 13.
# Re-running keeps /etc/proxycli/config.json and does not touch SSH.
set -euo pipefail

PROXYCLI_VERSION="1.0.0"
INSTALL_DIR="/opt/proxycli"
REPO_URL="https://github.com/driverm35/proxycli.git"
CADDY_IMAGE="caddy:2.11.7"
THREEPROXY_IMAGE="3proxy/3proxy:0.9.9.1"
DOCKER_CE_VERSION="29.8.2"

die() {
  echo "Ошибка: $*" >&2
  echo "Диагностика: cat /etc/os-release; uname -m; id; command -v docker; ss -ltnp | head" >&2
  exit 1
}

on_err() {
  local line="$1"
  echo "Сбой на строке ${line}." >&2
  exit 1
}

trap 'on_err "$LINENO"' ERR

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

install_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y python3 python3-venv python3-pip ca-certificates curl git nftables iproute2
  if command -v docker >/dev/null 2>&1; then
    local current
    current="$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)"
    if [[ "${current}" == "${DOCKER_CE_VERSION}" ]] && docker compose version >/dev/null 2>&1; then
      echo "Docker ${DOCKER_CE_VERSION} уже установлен"
      return 0
    fi
  fi
  # shellcheck disable=SC1091
  . /etc/os-release
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/${ID}/gpg" -o /etc/apt/keyrings/docker.asc \
    || die "не скачать ключ Docker. Диагностика: curl -I https://download.docker.com/linux/${ID}/gpg"
  chmod 0644 /etc/apt/keyrings/docker.asc
  local codename arch version
  codename="${VERSION_CODENAME}"
  arch="$(dpkg --print-architecture)"
  cat > /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/${ID}
Suites: ${codename}
Components: stable
Architectures: ${arch}
Signed-By: /etc/apt/keyrings/docker.asc
EOF
  apt-get update
  version="$(apt-cache madison docker-ce | awk -v v="${DOCKER_CE_VERSION}" 'index($0, v) { print $3; exit }')"
  if [[ -z "${version}" ]]; then
    die "пакет docker-ce ${DOCKER_CE_VERSION} не найден. Диагностика: apt-cache madison docker-ce"
  fi
  apt-get install -y "docker-ce=${version}" "docker-ce-cli=${version}" containerd.io docker-buildx-plugin docker-compose-plugin \
    || die "apt не установил Docker ${version}. Диагностика: apt-cache madison docker-ce"
  apt-mark hold docker-ce docker-ce-cli
}

enable_docker() {
  if ! command -v systemctl >/dev/null 2>&1; then
    die "systemd не найден, автозапуск Docker невозможен."
  fi
  systemctl enable --now docker
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

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
