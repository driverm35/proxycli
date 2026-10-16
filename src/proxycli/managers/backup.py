from __future__ import annotations

import json
import os
import re
import shutil
from datetime import UTC, datetime
from pathlib import Path

from proxycli.constants import SECRET_MODE
from proxycli.errors import ProxyCLIError
from proxycli.utils.paths import PathLayout

_ID = re.compile(r"^[0-9]{8}T[0-9]{6,}Z$")
_FILES = (
    "config.json",
    "secrets.json",
    "Caddyfile",
    "3proxy.cfg",
    "compose.yaml",
    "cloudflare.token",
)
_PRIVATE = {"secrets.json", "3proxy.cfg", "cloudflare.token"}


class BackupManager:
    def __init__(self, layout: PathLayout) -> None:
        self.layout = layout

    def create(self, reason: str) -> str:
        if not re.fullmatch(r"[a-z0-9._-]{1,64}", reason):
            raise ProxyCLIError("некорректная причина резервной копии")
        self.layout.ensure_dirs()
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        dest = self.layout.backup_dir / stamp
        dest.mkdir(parents=True)
        if os.name != "nt":
            os.chmod(dest, 0o700)
        saved: list[str] = []
        missing: list[str] = []
        for name in _FILES:
            source = self._path(name)
            if source.exists():
                target = dest / name
                shutil.copyfile(source, target)
                os.chmod(target, SECRET_MODE if name in _PRIVATE else 0o640)
                saved.append(name)
            else:
                missing.append(name)
        meta = {"reason": reason, "saved": saved, "missing": missing}
        (dest / "meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
        return stamp

    def restore(self, backup_id: str) -> None:
        dest = self._dir(backup_id)
        try:
            meta = json.loads((dest / "meta.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProxyCLIError(f"резервная копия {backup_id} повреждена") from exc
        for name in meta.get("saved", []):
            if name not in _FILES:
                raise ProxyCLIError("резервная копия содержит неожиданный файл")
            source = dest / name
            target = self._path(name)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            os.chmod(target, SECRET_MODE if name in _PRIVATE else 0o640)
        for name in meta.get("missing", []):
            if name not in _FILES:
                continue
            path = self._path(name)
            if path.exists():
                path.unlink()

    def list_ids(self) -> list[str]:
        if not self.layout.backup_dir.exists():
            return []
        return sorted(path.name for path in self.layout.backup_dir.iterdir() if _ID.fullmatch(path.name))

    def _dir(self, backup_id: str) -> Path:
        if not _ID.fullmatch(backup_id):
            raise ProxyCLIError("некорректный идентификатор копии")
        dest = self.layout.backup_dir / backup_id
        if not dest.is_dir():
            raise ProxyCLIError(f"копия {backup_id} не найдена", fix="proxycli backup list")
        return dest

    def _path(self, name: str) -> Path:
        return {
            "config.json": self.layout.config_file,
            "secrets.json": self.layout.secrets_file,
            "Caddyfile": self.layout.caddyfile,
            "3proxy.cfg": self.layout.proxy_cfg,
            "compose.yaml": self.layout.compose_file,
            "cloudflare.token": self.layout.token_file,
        }[name]
