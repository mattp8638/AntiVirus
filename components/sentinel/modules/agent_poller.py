import asyncio
import logging
from typing import Optional

from modules import storage

LOG = logging.getLogger("sentinel.agent_poller")


class AgentPoller:
    def __init__(self, interval: float = 5.0):
        self.interval = interval
        self._task: Optional[asyncio.Task] = None
        self._stopping = False

    async def poll_once(self):
        # Find pending investigation requests and mark them assigned for dispatch
        try:
            requests = [r for r in storage.list_investigation_requests() if r.get("status") == "pending"]
            for req in requests:
                request_id = req.get("request_id")
                LOG.info("Assigning investigation request %s", request_id)
                storage.update_investigation_request_status(request_id, "assigned")
                storage.save_audit_event(action="assign_investigation", entity_type="investigation_request", entity_id=request_id, details={"note":"auto-assigned by poller"})
        except Exception as exc:
            LOG.exception("Error during poll_once: %s", exc)

    async def _loop(self):
        while not self._stopping:
            await self.poll_once()
            await asyncio.sleep(self.interval)

    def start(self, loop: Optional[asyncio.AbstractEventLoop] = None) -> None:
        if self._task is not None:
            return
        if loop is None:
            loop = asyncio.get_event_loop()
        self._stopping = False
        self._task = loop.create_task(self._loop())

    async def stop(self) -> None:
        self._stopping = True
        if self._task:
            await asyncio.wait([self._task], timeout=5)
            self._task = None


poller = AgentPoller()
