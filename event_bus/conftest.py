"""Starts a real nats-server with JetStream. Set NATS_SERVER_BIN to the binary path.
Skipped if it is not found. AUDIT_DIR points at the audit-log folder (for the identifier check)."""
import asyncio
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

import pytest
import pytest_asyncio

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
sys.path.insert(0, REPO_ROOT)

import nats  # noqa: E402

from event_bus import BusConfig, ensure_streams  # noqa: E402


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def nats_url():
    binary = os.environ.get("NATS_SERVER_BIN") or shutil.which("nats-server")
    if not binary:
        pytest.skip("set NATS_SERVER_BIN to a nats-server binary to run the JetStream tests")
    port, d = _free_port(), tempfile.mkdtemp()
    proc = subprocess.Popen([binary, "-js", "-sd", d, "-a", "127.0.0.1", "-p", str(port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.05)
    yield f"nats://127.0.0.1:{port}"
    proc.terminate()
    proc.wait(timeout=10)
    shutil.rmtree(d, ignore_errors=True)


@pytest_asyncio.fixture
async def bus(nats_url):
    """A connection plus clean streams for every test."""
    nc = await nats.connect(nats_url)
    js = nc.jetstream()
    for s in ("CCQ_EVENTS", "CCQ_BATCH", "CCQ_USAGE", "CCQ_DEAD"):
        try:
            await js.delete_stream(s)
        except Exception:
            pass
    for attempt in range(10):          # the server removes a deleted stream's files asynchronously
        try:
            await ensure_streams(js, BusConfig())
            break
        except Exception:
            if attempt == 9:
                raise
            await asyncio.sleep(0.1)
    yield nc, js
    await nc.close()
