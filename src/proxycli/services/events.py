from __future__ import annotations

import json
from datetime import UTC, datetime

from proxycli.errors import ProxyCLIError
from proxycli.services.store import Store
from proxycli.utils.files import atomic_write
from proxycli.utils.paths import PathLayout
from proxycli.utils.redact import SENSITIVE_KEYS, contains_secret, redact_text


class EventLog:
    def __init__(self, layout: PathLayout, store: Store) -> None:
        self.layout = layout
        self.store = store

    def write(self, event: str, **fields: object) -> None:
        secrets = list(self._secrets())
        payload: dict[str, object] = {
            "ts": datetime.now(UTC).isoformat(),
            "event": event,
        }
        for key, value in fields.items():
            if key.lower() in SENSITIVE_KEYS:
                payload[key] = "***"
                continue
            if isinstance(value, str):
                payload[key] = redact_text(value, secrets)
            else:
                payload[key] = value
        line = json.dumps(payload, ensure_ascii=False)
        if contains_secret(line, secrets):
            raise ProxyCLIError("запись журнала отменена: в ней оказался секрет")
        path = self.layout.events_file
        self.layout.ensure_dirs()
        existing = path.read_text(encoding="utf-8") if path.exists() else ""
        atomic_write(path, existing + line + "\n", 0o640)

    def tail(self, limit: int = 50) -> list[dict[str, object]]:
        path = self.layout.events_file
        if not path.exists():
            return []
        rows = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                rows.append(item)
        return rows[-limit:]

    def _secrets(self) -> list[str]:
        try:
            return list(self.store.load_secrets().values())
        except ProxyCLIError:
            return []
