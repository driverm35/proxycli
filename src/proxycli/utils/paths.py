from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class PathLayout:
    config_file: Path
    secrets_file: Path
    token_file: Path
    log_dir: Path
    backup_dir: Path
    deploy_dir: Path
    firewall_state: Path
    app_dir: Path

    @staticmethod
    def from_env() -> PathLayout:
        state = os.environ.get("PROXYCLI_STATE_DIR")
        if state:
            return PathLayout._under(Path(state), app_dir=Path(state) / "opt" / "proxycli" / "src")
        if os.name == "posix":
            return PathLayout(
                config_file=Path("/etc/proxycli/config.json"),
                secrets_file=Path("/etc/proxycli/secrets.json"),
                token_file=Path("/etc/proxycli/cloudflare.token"),
                log_dir=Path("/var/log/proxycli"),
                backup_dir=Path("/var/lib/proxycli/backups"),
                deploy_dir=Path("/var/lib/proxycli/deploy"),
                firewall_state=Path("/var/lib/proxycli/firewall-rules.json"),
                app_dir=Path("/opt/proxycli/src"),
            )
        root = Path.home() / ".proxycli"
        return PathLayout._under(root, app_dir=root / "src")

    @staticmethod
    def _under(root: Path, app_dir: Path) -> PathLayout:
        return PathLayout(
            config_file=root / "etc" / "proxycli" / "config.json",
            secrets_file=root / "etc" / "proxycli" / "secrets.json",
            token_file=root / "etc" / "proxycli" / "cloudflare.token",
            log_dir=root / "var" / "log" / "proxycli",
            backup_dir=root / "var" / "lib" / "proxycli" / "backups",
            deploy_dir=root / "var" / "lib" / "proxycli" / "deploy",
            firewall_state=root / "var" / "lib" / "proxycli" / "firewall-rules.json",
            app_dir=app_dir,
        )

    @property
    def caddyfile(self) -> Path:
        return self.deploy_dir / "caddy" / "Caddyfile"

    @property
    def proxy_cfg(self) -> Path:
        return self.deploy_dir / "3proxy" / "3proxy.cfg"

    @property
    def compose_file(self) -> Path:
        return self.deploy_dir / "compose.yaml"

    @property
    def dockerfile(self) -> Path:
        return self.deploy_dir / "caddy" / "Dockerfile"

    @property
    def entrypoint(self) -> Path:
        return self.deploy_dir / "caddy" / "entrypoint.sh"

    @property
    def events_file(self) -> Path:
        return self.log_dir / "events.jsonl"

    def ensure_dirs(self) -> None:
        from proxycli.constants import BACKUP_DIR_MODE

        for directory in (
            self.config_file.parent,
            self.log_dir,
            self.backup_dir,
            self.caddyfile.parent,
            self.proxy_cfg.parent,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(self.config_file.parent, 0o750)
            os.chmod(self.log_dir, 0o750)
            os.chmod(self.backup_dir, BACKUP_DIR_MODE)
