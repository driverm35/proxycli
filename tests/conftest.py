
import pytest

from proxycli.utils.paths import PathLayout


@pytest.fixture
def layout(tmp_path, monkeypatch):
    monkeypatch.setenv("PROXYCLI_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("PROXYCLI_OFFLINE", "1")
    monkeypatch.delenv("PROXYCLI_FAIL_STEP", raising=False)
    monkeypatch.delenv("PROXYCLI_SKIP_PROBES", raising=False)
    lay = PathLayout.from_env()
    lay.ensure_dirs()
    return lay


@pytest.fixture
def stack(layout):
    from proxycli.managers.stack import Stack

    return Stack(layout)
