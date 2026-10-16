from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from typing import Protocol

from proxycli.errors import ProxyCLIError, ValidationError


@dataclass
class ProcResult:
    code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.code == 0


class Runner(Protocol):
    def __call__(self, argv: list[str], timeout: float = 30) -> ProcResult: ...


def _check_argv(argv: list[str]) -> None:
    if not argv or not all(isinstance(part, str) and part != "" for part in argv):
        raise ValidationError("команда должна быть непустым списком аргументов")
    for part in argv:
        if "\x00" in part or "\n" in part or "\r" in part:
            raise ValidationError("аргумент команды содержит запрещённые символы")


class SubprocessRunner:
    def __call__(self, argv: list[str], timeout: float = 30) -> ProcResult:
        _check_argv(argv)
        try:
            completed = subprocess.run(
                argv,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise ProxyCLIError(
                f"таймаут команды: {argv[0]}",
                fix=f"проверьте, не зависла ли команда: {argv[0]}",
            ) from exc
        except FileNotFoundError as exc:
            raise ProxyCLIError(
                f"команда не найдена: {argv[0]}",
                fix=f"command -v {argv[0]}",
            ) from exc
        return ProcResult(completed.returncode, completed.stdout, completed.stderr)


class OfflineRunner:
    """Test seam. A zero exit here is not a TLS or firewall success."""

    def __init__(self, fail_step: str = "") -> None:
        self.fail_step = fail_step
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], timeout: float = 30) -> ProcResult:
        _check_argv(argv)
        self.calls.append(list(argv))
        if self.fail_step and self.fail_step in argv:
            return ProcResult(1, "", f"симулированный сбой {self.fail_step}")
        return ProcResult(0, "", "")


def make_runner() -> Runner:
    if os.environ.get("PROXYCLI_OFFLINE") == "1":
        return OfflineRunner(os.environ.get("PROXYCLI_FAIL_STEP", ""))
    return SubprocessRunner()


def require_ok(result: ProcResult, argv: list[str]) -> ProcResult:
    if result.ok:
        return result
    detail = (result.stderr or result.stdout or "ненулевой код").strip()
    command = " ".join(argv)
    raise ProxyCLIError(f"команда завершилась с ошибкой ({command}): {detail}")
