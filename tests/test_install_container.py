import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "install.sh"


def _docker_ready() -> bool:
    docker = shutil.which("docker")
    if not docker:
        return False
    try:
        result = subprocess.run([docker, "info"], capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


pytestmark = pytest.mark.skipif(
    not _docker_ready(),
    reason="docker недоступен: проверка install.sh в контейнере пропущена",
)


def test_piped_dry_run_in_ubuntu_container():
    result = subprocess.run(
        ["docker", "run", "--rm", "-i", "ubuntu:24.04", "bash", "-s", "--", "--dry-run"],
        input=SCRIPT.read_bytes(),
        capture_output=True,
        timeout=300,
    )
    stdout = result.stdout.decode("utf-8", "replace")
    stderr = result.stderr.decode("utf-8", "replace")
    assert result.returncode == 0, stderr or stdout
    assert "invalid option" not in stdout
    assert "invalid option" not in stderr
    assert "dry-run: установка не выполняется" in stdout
    assert "Docker CE 29.8.2" in stdout
    assert "Caddy caddy:2.11.7" in stdout
    assert "3proxy 3proxy/3proxy:0.9.9.1" in stdout


def test_setup_logging_banner_reaches_install_log():
    # Exit the logging shell first so tee flushes the file before we read it.
    inner = (
        "source /install.sh\n"
        "INSTALL_LOG=/tmp/proxycli-logdir/install.log\n"
        "setup_logging\n"
        "echo AFTER_BANNER\n"
    )
    command = (
        "set -euo pipefail; "
        f"bash -c {shlex.quote(inner)}; "
        "echo ---LOG---; "
        "cat /tmp/proxycli-logdir/install.log"
    )
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{SCRIPT}:/install.sh:ro",
            "ubuntu:24.04",
            "bash",
            "-c",
            command,
        ],
        capture_output=True,
        timeout=120,
    )
    stdout = result.stdout.decode("utf-8", "replace")
    stderr = result.stderr.decode("utf-8", "replace")
    assert result.returncode == 0, stderr or stdout
    assert "invalid option" not in stdout
    assert "invalid option" not in stderr
    banner, _, saved = stdout.partition("---LOG---")
    assert "---- proxycli install " in banner
    assert "AFTER_BANNER" in banner
    assert "---- proxycli install " in saved
    assert "AFTER_BANNER" in saved


def test_logging_flushes_failure_before_exit():
    inner = (
        "source /install.sh\n"
        "INSTALL_LOG=/tmp/proxycli-logdir/install.log\n"
        "setup_logging\n"
        "false\n"
    )
    command = (
        "bash -c "
        + shlex.quote(inner)
        + "; status=$?; echo ---LOG---; cat /tmp/proxycli-logdir/install.log; exit $status"
    )
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{SCRIPT}:/install.sh:ro",
            "ubuntu:24.04",
            "bash",
            "-c",
            command,
        ],
        capture_output=True,
        timeout=120,
    )
    stdout = result.stdout.decode("utf-8", "replace")
    stderr = result.stderr.decode("utf-8", "replace")
    assert result.returncode != 0, stdout
    assert "invalid option" not in stdout
    assert "invalid option" not in stderr
    banner, _, saved = stdout.partition("---LOG---")
    assert "Ошибка установки" in banner
    assert "Команда: false" in banner
    assert "---- proxycli install " in saved
    assert "Ошибка установки" in saved
    assert "Команда: false" in saved
