# coordinator.py
import asyncio
import aiohttp
from aiohttp import web
import json
import uuid
from datetime import datetime
from typing import Dict, Set

class Coordinator:
    def __init__(self):
        self.nodes: Dict[str, dict] = {}          # node_id -> {ip, port, last_heartbeat, load}
        self.task_queue = asyncio.Queue()
        self.pending_tasks: Dict[str, dict] = {}
        self.lock = asyncio.Lock()

    async def register_node(self, request):
        data = await request.json()
        node_id = data["node_id"]
        async with self.lock:
            self.nodes[node_id] = {
                "ip": data["ip"],
                "port": data["port"],
                "last_heartbeat": datetime.now().isoformat(),
                "load": data.get("load", 0),
                "capabilities": data.get("capabilities", ["scan"])
            }
        return web.json_response({"status": "registered"})

    async def heartbeat(self, request):
        data = await request.json()
        node_id = data["node_id"]
        async with self.lock:
            if node_id in self.nodes:
                self.nodes[node_id]["last_heartbeat"] = datetime.now().isoformat()
                self.nodes[node_id]["load"] = data.get("load", 0)
        return web.Response(status=200)

    async def get_task(self, request):
        """Worker asks for a task (long polling)."""
        try:
            task = await asyncio.wait_for(self.task_queue.get(), timeout=5)
        except asyncio.TimeoutError:
            return web.json_response({"task": None})
        return web.json_response(task)

    async def submit_result(self, request):
        data = await request.json()
        task_id = data["task_id"]
        result = data["result"]
        if task_id in self.pending_tasks:
            self.pending_tasks[task_id]["result"] = result
            # Store in DB, notify client, etc.
        return web.Response(status=200)

    async def submit_scan(self, target: str, scan_type: str = "comprehensive"):
        task_id = str(uuid.uuid4())
        task = {"task_id": task_id, "target": target, "type": scan_type}
        self.pending_tasks[task_id] = task
        await self.task_queue.put(task)
        return task_id

    async def start(self):
        app = web.Application()
        app.router.add_post("/register", self.register_node)
        app.router.add_post("/heartbeat", self.heartbeat)
        app.router.add_get("/task", self.get_task)
        app.router.add_post("/result", self.submit_result)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "0.0.0.0", 8080)
        await site.start()
        logging.info("Coordinator listening on port 8080")
        # Keep running
        await asyncio.Event().wait()