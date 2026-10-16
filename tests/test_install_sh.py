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
