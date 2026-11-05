"""Exercise the actual server lifecycle and HTTP auth gates after API upgrades.

Requires the disposable PostgreSQL and Redis services configured by CI.
"""

import socket
import signal
import subprocess
import sys
import tempfile
import time

import requests


def test_server_starts_serves_protected_routes_and_shuts_down():
    with socket.socket() as listener, tempfile.TemporaryFile(mode="w+") as log:
        listener.bind(("127.0.0.1", 0))
        base = f"http://127.0.0.1:{listener.getsockname()[1]}"
        process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "src.server_init:app", "--fd", str(listener.fileno())],
            pass_fds=(listener.fileno(),),
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    if requests.get(f"{base}/health", timeout=1).status_code == 200:
                        break
                except requests.RequestException:
                    pass
                time.sleep(0.1)
            else:
                log.seek(0)
                raise AssertionError(f"Engine did not become healthy:\n{log.read()[-4000:]}")

            # These requests pass through Uvicorn, the production middleware,
            # lifespan-installed routers and real dependency injection.
            response = requests.post(f"{base}/decision", json={}, timeout=5)
            assert response.status_code == 401, response.text
            assert "riskLevel" not in response.text
            response = requests.post(
                f"{base}/decision", json={},
                headers={"Authorization": "Bearer not.a.token"}, timeout=5,
            )
            assert response.status_code == 401, response.text
            assert requests.get(f"{base}/health/detail", timeout=5).status_code == 401
            response = requests.post(f"{base}/login_event/webhook", json={}, timeout=5)
            assert response.status_code == 401, response.text
            response = requests.get(f"{base}/openapi.json", timeout=5)
            assert response.status_code == 200
            assert "/decision" in response.json()["paths"]
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

        assert process.returncode in (0, -signal.SIGTERM)
        log.seek(0)
        assert "Application shutdown complete" in log.read()
