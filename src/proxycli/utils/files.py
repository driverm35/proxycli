"""Atomic writes and permission tightening."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def chmod(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        if os.name != "nt":
            raise


def atomic_write(path: Path, data: str, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(data)
        chmod(tmp, mode)
        os.replace(tmp, path)
        chmod(path, mode)
    except Exception:
        if tmp.exists():
            tmp.unlink()
        raise


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")
