import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("LLM_PROVIDER", "offline")

from backend.common.chain import Chain  # noqa: E402
from backend.devchain import DevChain  # noqa: E402
from backend.system import CascadeShieldSystem  # noqa: E402


def adv(n: int) -> str:
    return (ROOT / "data" / "advisories" / f"ADV-2023-{n:04d}.txt").read_text(encoding="utf-8")


@pytest.fixture(scope="session")
def devchain():
    dc = DevChain().start()
    yield dc
    dc.stop()


@pytest.fixture(scope="session")
def system(devchain, tmp_path_factory):
    state = tmp_path_factory.mktemp("state_main")
    s = CascadeShieldSystem(devchain.url, str(devchain.deployment_file), state)
    s.boot = s.bootstrap()
    return s


@pytest.fixture()
def offline_node(tmp_path):
    """A real OrgNodeRuntime that is NOT connected to any chain (planner / critic / parser tests)."""
    from backend.agents.org_node import OrgNodeRuntime
    from backend.common.chain import ChainWriter

    chain = Chain("http://127.0.0.1:9", deployment_file=str(tmp_path / "none.json"))
    writer = ChainWriter(chain, tmp_path / "w.db")
    return OrgNodeRuntime("power", chain, writer, tmp_path)
