"""main.RequestGate: at most N HTTP requests inside the app at once, so threads and DB connections can't deadlock."""

import asyncio

from fenrir_cloud.main import RequestGate


def test_requests_beyond_the_limit_wait_and_health_and_websockets_pass():
    inside, peak = 0, 0

    async def app(scope, receive, send):
        nonlocal inside, peak
        inside += 1
        peak = max(peak, inside)
        await asyncio.sleep(0.02)
        inside -= 1

    async def run():
        gate = RequestGate(app, limit=3)
        calls = [gate({"type": "http", "path": "/api/v1/x"}, None, None) for _ in range(12)]
        await asyncio.gather(*calls)
        assert peak == 3
        # Health checks and WebSockets go straight through, even with the gate full.
        await asyncio.gather(*[gate({"type": "http", "path": "/api/v1/x"}, None, None) for _ in range(3)],
                             gate({"type": "http", "path": "/health/background"}, None, None),
                             gate({"type": "websocket", "path": "/relay"}, None, None))
        assert peak == 5 and gate.waiting == 0

    asyncio.run(run())
