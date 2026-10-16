from __future__ import annotations

import shutil
import tarfile
from pathlib import Path

from proxycli.constants import APP_VERSION, GITHUB_REPO
from proxycli.errors import ProxyCLIError
from proxycli.managers.stack import Stack


def check_update(stack: Stack) -> str:
    local = f"Локальная версия {APP_VERSION}."
    if stack.offline():
        return local + " Удалённая версия не проверялась (offline), актуальность не заявляется."
    argv = ["git", "ls-remote", GITHUB_REPO, "HEAD"]
    try:
        result = stack.runner(argv, timeout=20)
    except ProxyCLIError as exc:
        return local + f" Удалённая версия неизвестна: {exc}"
    if not result.ok:
        detail = (result.stderr or result.stdout or "git ls-remote").strip()
        return local + f" Удалённая версия неизвестна: {detail}"
    head = result.stdout.strip() or "пусто"
    return local + f" HEAD на GitHub: {head}. Совпадение с локальным коммитом здесь не проверялось."


def apply_update(stack: Stack) -> str:
    if stack.offline():
        raise ProxyCLIError("обновление не выполняется в PROXYCLI_OFFLINE")
    apps, pips = update_path_candidates(stack.layout.app_dir)
    app, pip = select_update_paths(apps, pips)
    snap = stack.backup.create("update")
    archive = stack.layout.backup_dir / snap / "app.tar.gz"
    archive_tree(app, archive)
    pull = stack.runner(["git", "-C", str(app), "pull", "--ff-only"], timeout=120)
    if not pull.ok:
        restore_tree(archive, app)
        raise ProxyCLIError(
            (pull.stderr or "git pull --ff-only не удался").strip(),
            fix=f"proxycli backup restore --id {snap}",
        )
    installed = stack.runner([str(pip), "install", str(app)], timeout=300)
    if not installed.ok:
        restore_tree(archive, app)
        raise ProxyCLIError("pip install не удался, исходники восстановлены из копии")
    try:
        stack.reload(probe=False)
    except Exception:
        restore_tree(archive, app)
        stack.backup.restore(snap)
        stack.runner([str(pip), "install", str(app)], timeout=300)
        stack.reload(probe=False, simulate_failure=False)
        raise
    stack.events.write("update.apply", version=APP_VERSION)
    return "обновление применено; конфигурация и секреты сохранены через резервную копию"


def archive_tree(src: Path, dest: Path) -> None:
    _refuse_etc_proxycli(src)
    with tarfile.open(dest, "w:gz") as archive:
        archive.add(src, arcname=src.name)


def restore_tree(archive_path: Path, dest: Path) -> None:
    _refuse_etc_proxycli(dest)
    parent = dest.parent
    parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        shutil.rmtree(dest)
    with tarfile.open(archive_path, "r:gz") as archive:
        _ensure_members(archive, parent)
        archive.extractall(parent, filter="data")


def _ensure_members(archive: tarfile.TarFile, parent: Path) -> None:
    root = parent.resolve()
    for member in archive.getmembers():
        if member.issym() or member.islnk():
            raise ProxyCLIError("архив приложения содержит ссылку и отклонён")
        target = (root / member.name).resolve()
        if root != target and root not in target.parents:
            raise ProxyCLIError("архив приложения содержит небезопасный путь")


def update_path_candidates(app_dir: Path) -> tuple[list[Path], list[Path]]:
    apps: list[Path] = []
    for candidate in (Path("/opt/proxycli"), app_dir):
        if candidate not in apps:
            apps.append(candidate)
    pips: list[Path] = []
    for candidate in (
        Path("/opt/proxycli/.venv/bin/pip"),
        app_dir / ".venv" / "bin" / "pip",
        Path("/opt/proxycli/venv/bin/pip"),
        app_dir / "venv" / "bin" / "pip",
    ):
        if candidate not in pips:
            pips.append(candidate)
    return apps, pips


def select_update_paths(app_candidates: list[Path], pip_candidates: list[Path]) -> tuple[Path, Path]:
    saw_protected = False
    app: Path | None = None
    for candidate in app_candidates:
        if not _outside_etc_proxycli(candidate):
            saw_protected = True
            continue
        if (candidate / "pyproject.toml").is_file() and (candidate / ".git").is_dir():
            app = candidate
            break
    if app is None:
        if saw_protected and not any(_outside_etc_proxycli(item) for item in app_candidates):
            raise ProxyCLIError("обновление не изменяет /etc/proxycli")
        raise ProxyCLIError(
            "каталог приложения не является git-клоном",
            fix="sudo bash install.sh",
        )
    pip = next(
        (item for item in pip_candidates if item.is_file() and _outside_etc_proxycli(item)),
        None,
    )
    if pip is None:
        raise ProxyCLIError(
            "не найден /opt/proxycli/.venv/bin/pip",
            fix="sudo bash install.sh",
        )
    return app, pip


def _refuse_etc_proxycli(path: Path) -> None:
    if not _outside_etc_proxycli(path):
        raise ProxyCLIError("обновление не изменяет /etc/proxycli")


def _outside_etc_proxycli(path: Path) -> bool:
    protected = "/etc/proxycli"
    texts = [path.as_posix().rstrip("/")]
    try:
        texts.append(path.resolve().as_posix().rstrip("/"))
    except OSError:
        return False
    return all(text != protected and not text.startswith(protected + "/") for text in texts)
