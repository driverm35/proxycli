from __future__ import annotations

import json
import os
import secrets
import string
from pathlib import Path

from proxycli.constants import CONFIG_MODE, SECRET_MODE
from proxycli.errors import ProxyCLIError, ValidationError
from proxycli.models.config import AppConfig
from proxycli.utils.files import atomic_write
from proxycli.utils.paths import PathLayout
from proxycli.utils.validation import validate_password, validate_token


def generate_password(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


class Store:
    def __init__(self, layout: PathLayout) -> None:
        self.layout = layout

    def load(self) -> AppConfig:
        path = self.layout.config_file
        if not path.exists():
            return AppConfig()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ProxyCLIError(
                f"config.json повреждён: {exc.msg}",
                fix=f"python -m json.tool {path}",
            ) from exc
        if not isinstance(data, dict):
            raise ProxyCLIError("config.json должен быть объектом")
        try:
            return AppConfig.from_dict(data)
        except (KeyError, TypeError, ValueError) as exc:
            raise ProxyCLIError(f"config.json не читается: {exc}") from exc

    def save(self, config: AppConfig) -> None:
        payload = json.dumps(config.to_dict(), ensure_ascii=False, indent=2) + "\n"
        self._reject_secrets_in_config(payload)
        self.layout.ensure_dirs()
        atomic_write(self.layout.config_file, payload, CONFIG_MODE)

    def load_secrets(self) -> dict[str, str]:
        path = self.layout.secrets_file
        if not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ProxyCLIError(
                "secrets.json повреждён",
                fix=f"проверьте JSON, не печатайте файл в общий журнал: {path}",
            ) from exc
        if not isinstance(data, dict) or not all(isinstance(v, str) for v in data.values()):
            raise ProxyCLIError("secrets.json должен быть объектом строк")
        return {str(key): value for key, value in data.items()}

    def save_secrets(self, secrets_map: dict[str, str]) -> None:
        payload = json.dumps(secrets_map, ensure_ascii=False, indent=2) + "\n"
        self.layout.ensure_dirs()
        atomic_write(self.layout.secrets_file, payload, SECRET_MODE)

    def set_secret(self, ref: str, value: str) -> None:
        current = self.load_secrets()
        current[ref] = value
        self.save_secrets(current)

    def delete_secret(self, ref: str) -> None:
        current = self.load_secrets()
        current.pop(ref, None)
        self.save_secrets(current)

    def write_token(self, token: str) -> None:
        cleaned = validate_token(token)
        self.layout.ensure_dirs()
        atomic_write(self.layout.token_file, cleaned + "\n", SECRET_MODE)
        self.set_secret("cloudflare_token", cleaned)

    def read_token_file(self, path: Path) -> str:
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ProxyCLIError(f"не удалось прочитать файл токена: {exc}") from exc
        return validate_token(raw.strip())

    def _reject_secrets_in_config(self, payload: str) -> None:
        try:
            secrets_map = self.load_secrets()
        except ProxyCLIError:
            secrets_map = {}
        for value in secrets_map.values():
            if value and len(value) >= 4 and value in payload:
                raise ValidationError("в config.json нельзя записывать секреты")


def password_from_file(path: Path) -> str:
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ProxyCLIError(f"не удалось прочитать файл пароля: {exc}") from exc
    return validate_password(raw)


def file_mode(path: Path) -> int | None:
    if not path.exists() or os.name == "nt":
        return None
    return path.stat().st_mode & 0o777
