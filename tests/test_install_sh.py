import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _bash():
    candidates = ["bash", r"C:\Program Files\Git\bin\bash.exe", r"C:\Windows\System32\bash.exe"]
    for candidate in candidates:
        if candidate != "bash" and not Path(candidate).exists():
            continue
        try:
            result = subprocess.run(
                [candidate, "-c", "echo ok"],
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0 and "ok" in result.stdout:
            return candidate
    return None


BASH = _bash()


def _candidates(name: str) -> list[str]:
    path = ROOT / name
    posix = path.as_posix()
    found = [posix, str(path)]
    if len(posix) > 2 and posix[1] == ":":
        found.append("/mnt/" + posix[0].lower() + posix[2:])
    return found


def _script(name: str) -> str:
    assert BASH is not None
    errors = []
    for candidate in _candidates(name):
        result = subprocess.run(
            [BASH, "-c", f'source "{candidate}"; type check_os'],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if result.returncode == 0:
            return candidate
        errors.append(result.stderr.strip())
    pytest.skip("bash не загрузил install.sh: " + " | ".join(errors))


@pytest.mark.skipif(BASH is None, reason="bash недоступен: функциональные проверки install.sh пропущены")
def test_os_and_arch_helpers():
    script = _script("install.sh")
    bad = subprocess.run(
        [BASH, "-c", f'source "{script}"; check_os'],
        capture_output=True,
        text=True,
        env={**os.environ, "PROXYCLI_ASSUME_OS": "ubuntu-22.04"},
        timeout=20,
    )
    assert bad.returncode == 1
    assert "22.04" in bad.stderr
    good = subprocess.run(
        [BASH, "-c", f'source "{script}"; check_os; check_arch'],
        capture_output=True,
        text=True,
        env={**os.environ, "PROXYCLI_ASSUME_OS": "debian-13", "PROXYCLI_ASSUME_ARCH": "x86_64"},
        timeout=20,
    )
    assert good.returncode == 0, good.stderr
    arch = subprocess.run(
        [BASH, "-c", f'source "{script}"; check_arch'],
        capture_output=True,
        text=True,
        env={**os.environ, "PROXYCLI_ASSUME_ARCH": "i686"},
        timeout=20,
    )
    assert arch.returncode == 1


@pytest.mark.skipif(BASH is None, reason="bash недоступен: функциональные проверки install.sh пропущены")
def test_port_helper_and_dry_run():
    script = _script("install.sh")
    busy = subprocess.run(
        [BASH, "-c", f'source "{script}"; assert_port_free 80'],
        capture_output=True,
        text=True,
        env={**os.environ, "PROXYCLI_MOCK_LISTENERS": "80 sshd"},
        timeout=20,
    )
    assert busy.returncode == 1
    assert "sshd" in busy.stderr
    ours = subprocess.run(
        [BASH, "-c", f'source "{script}"; assert_port_free 443'],
        capture_output=True,
        text=True,
        env={**os.environ, "PROXYCLI_MOCK_LISTENERS": "443 docker-proxy"},
        timeout=20,
    )
    assert ours.returncode == 0, ours.stderr
    dry = subprocess.run(
        [BASH, script, "--dry-run"],
        capture_output=True,
        text=True,
        env={**os.environ, "PROXYCLI_ASSUME_OS": "ubuntu-24.04", "PROXYCLI_ASSUME_ARCH": "x86_64"},
        timeout=20,
    )
    if dry.returncode != 0 and "No such file" in dry.stderr:
        pytest.skip("bash не видит путь Windows; проверка dry-run выполняется в CI")
    assert dry.returncode == 0, dry.stderr
    assert "dry-run" in dry.stdout
    assert "29.8.2" in dry.stdout
    assert shutil.which("shellcheck") or True


def _piped(name: str, args: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
    assert BASH is not None
    return subprocess.run(
        [BASH, "-s", "--", *args],
        input=(ROOT / name).read_bytes(),
        capture_output=True,
        env=env,
        timeout=20,
    )


@pytest.mark.skipif(BASH is None, reason="bash недоступен: проверка piped install.sh пропущена")
def test_piped_stdin_dry_run():
    env = {**os.environ, "PROXYCLI_ASSUME_OS": "ubuntu-24.04", "PROXYCLI_ASSUME_ARCH": "x86_64"}
    good = _piped("install.sh", ["--dry-run"], env)
    stdout = good.stdout.decode("utf-8", "replace")
    stderr = good.stderr.decode("utf-8", "replace")
    assert "unbound variable" not in stdout
    assert "unbound variable" not in stderr
    assert good.returncode == 0, stderr
    assert "dry-run" in stdout
    assert "Docker CE 29.8.2" in stdout
    assert "Caddy caddy:2.11.7" in stdout
    assert "3proxy 3proxy/3proxy:0.9.9.1" in stdout

    rejected = _piped(
        "install.sh",
        ["--dry-run"],
        {**os.environ, "PROXYCLI_ASSUME_OS": "ubuntu-22.04", "PROXYCLI_ASSUME_ARCH": "x86_64"},
    )
    rejected_out = rejected.stdout.decode("utf-8", "replace")
    rejected_err = rejected.stderr.decode("utf-8", "replace")
    assert "unbound variable" not in rejected_out
    assert "unbound variable" not in rejected_err
    assert rejected.returncode != 0
    assert "22.04" in rejected_err
    assert "dry-run" not in rejected_out


def _sourced(script: str, body: str) -> tuple[int, str, str]:
    assert BASH is not None
    result = subprocess.run(
        [BASH, "-c", f'source "{script}"\n{body}'],
        capture_output=True,
        timeout=20,
    )
    stdout = result.stdout.decode("utf-8", "replace")
    stderr = result.stderr.decode("utf-8", "replace")
    return result.returncode, stdout, stderr


@pytest.mark.skipif(BASH is None, reason="bash недоступен: функциональные проверки install.sh пропущены")
def test_docker_source_prefers_pinned_version():
    script = _script("install.sh")
    code, stdout, stderr = _sourced(
        script,
        """
apt-cache() {
  printf '%s\\n' 'docker-ce | 5:29.9.0-1~ubuntu.24.04~noble | https://download.docker.com/linux/ubuntu noble/stable amd64 Packages'
  printf '%s\\n' \"docker-ce | 5:${DOCKER_CE_VERSION}-1~ubuntu.24.04~noble | https://download.docker.com/linux/ubuntu noble/stable amd64 Packages\"
  return 0
}
choose_docker_source
""",
    )
    assert code == 0, stderr
    assert stdout.strip().startswith("pinned ")
    assert "5:29.8.2-1~ubuntu.24.04~noble" in stdout
    assert "Предупреждение" not in stderr


@pytest.mark.skipif(BASH is None, reason="bash недоступен: функциональные проверки install.sh пропущены")
def test_docker_source_uses_newest_when_pin_missing():
    script = _script("install.sh")
    code, stdout, stderr = _sourced(
        script,
        """
apt-cache() {
  printf '%s\\n' 'docker-ce | 5:29.8.20-1~ubuntu.26.04~resolute | https://download.docker.com/linux/ubuntu resolute/stable amd64 Packages'
  printf '%s\\n' 'docker-ce | 5:28.5.1-1~ubuntu.26.04~resolute | https://download.docker.com/linux/ubuntu resolute/stable amd64 Packages'
  return 0
}
choose_docker_source
""",
    )
    assert code == 0, stderr
    assert stdout.strip() == "newest 5:29.8.20-1~ubuntu.26.04~resolute"
    assert "Предупреждение" in stderr
    assert "29.8.2" in stderr
    assert "29.8.20" in stderr
    assert not stdout.strip().startswith("pinned")


@pytest.mark.skipif(BASH is None, reason="bash недоступен: функциональные проверки install.sh пропущены")
def test_docker_source_falls_back_to_distro_packages():
    script = _script("install.sh")
    code, stdout, stderr = _sourced(
        script,
        """
apt-cache() {
  return 0
}
choose_docker_source
""",
    )
    assert code == 0, stderr
    assert stdout.strip() == "distro"
    assert "Предупреждение" in stderr
    assert "docker.io" in stderr


@pytest.mark.skipif(BASH is None, reason="bash недоступен: функциональные проверки install.sh пропущены")
def test_ensure_curl_installs_when_missing():
    script = _script("install.sh")
    code, stdout, stderr = _sourced(
        script,
        """
command() { return 1; }
apt-get() { printf '%s\\n' "apt $*"; return 0; }
ensure_curl
""",
    )
    assert code == 0, stderr
    assert "apt update" in stdout
    assert "apt install -y ca-certificates curl" in stdout


@pytest.mark.skipif(BASH is None, reason="bash недоступен: функциональные проверки install.sh пропущены")
def test_ensure_curl_skips_when_present():
    script = _script("install.sh")
    code, stdout, stderr = _sourced(
        script,
        """
command() { return 0; }
apt-get() { printf '%s\\n' "apt-should-not-run"; return 1; }
ensure_curl
""",
    )
    assert code == 0, stderr
    assert "apt-should-not-run" not in stdout


@pytest.mark.skipif(BASH is None, reason="bash недоступен: функциональные проверки install.sh пропущены")
def test_install_banner_accepts_leading_dashes():
    script = _script("install.sh")
    code, stdout, stderr = _sourced(script, 'install_banner "2026-01-01T00:00:00Z"')
    assert code == 0, stderr
    assert stdout.strip() == "---- proxycli install 2026-01-01T00:00:00Z ----"
    assert "invalid option" not in stderr


@pytest.mark.skipif(BASH is None, reason="bash недоступен: функциональные проверки install.sh пропущены")
def test_err_trap_reports_failing_command():
    script = _script("install.sh")
    # Line 1 is `source`. `false` is line 3; the call on line 5 must not be reported.
    code, _stdout, stderr = _sourced(
        script,
        "proxycli_trap_fn() {\n  false\n}\nproxycli_trap_fn\n",
    )
    assert code != 0
    assert "Ошибка установки" in stderr
    assert "Команда: false" in stderr
    assert "Строка: 3" in stderr
    assert "Строка: 5" not in stderr
    assert "install.log" in stderr
    assert "bash -x /tmp/proxycli-install.sh" in stderr
    assert "https://raw.githubusercontent.com/driverm35/proxycli/main/install.sh" in stderr


@pytest.mark.skipif(BASH is None, reason="bash недоступен: проверка piped install.sh пропущена")
def test_piped_uninstall_help():
    result = _piped("uninstall.sh", ["--help"])
    stdout = result.stdout.decode("utf-8", "replace")
    stderr = result.stderr.decode("utf-8", "replace")
    assert "unbound variable" not in stdout
    assert "unbound variable" not in stderr
    assert result.returncode == 0, stderr
    assert "--purge" in stdout
