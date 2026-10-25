"""Real loopback TCP transport; business faults stay in the serving process."""
import socket
import threading
import httpx
import uvicorn


def test_real_tcp_health(http, monkeypatch, evidence):
    from main import app
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(16)
    port = listener.getsockname()[1]
    # Explicitly permit this one loopback socket in the test process network guard.
    from scripts.security_isolation import safety
    safety.LOCAL_HTTP_ENDPOINTS.add(('127.0.0.1', port))
    ready = threading.Event()
    server = uvicorn.Server(uvicorn.Config(app, host='127.0.0.1', port=port,
        lifespan='off', access_log=False, log_config=None))
    original = server.startup
    async def startup(sockets=None):
        await original(sockets=sockets)
        ready.set()
    monkeypatch.setattr(server, 'startup', startup)
    worker = threading.Thread(target=lambda: server.run(sockets=[listener]), daemon=True)
    worker.start()
    try:
        assert ready.wait(15), 'loopback HTTP server startup timed out'
        with httpx.Client(trust_env=False, timeout=10) as client:
            response = client.get(f'http://127.0.0.1:{port}/health')
        assert response.status_code == 200
        evidence({'transport': 'real-loopback-TCP', 'status': response.status_code})
    finally:
        server.should_exit = True
        worker.join(15)
        listener.close()
        safety.LOCAL_HTTP_ENDPOINTS.discard(('127.0.0.1', port))
        assert not worker.is_alive(), 'loopback server failed to terminate'
