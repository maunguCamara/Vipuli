# coordinator.py
import logging
import asyncio
import aiohttp
from aiohttp import web
import json
import uuid
from datetime import datetime
from typing import Dict, Set
logging.basicConfig(level=logging.INFO)
from config import get_config

API_KEY = os.environ["COORDINATOR_API_KEY"]
        
class Coordinator:
    def __init__(self):
        self.nodes: Dict[str, dict] = {}          # node_id -> {ip, port, last_heartbeat, load}
        self.task_queue = asyncio.Queue()
        self.pending_tasks: Dict[str, dict] = {}
        self.lock = asyncio.Lock()
    
    async def main():
        parser = argparse.ArgumentParser()
        parser.add_argument("-c", "--config", default="config.yaml")
        args = parser.parse_args()
        
        # Load config once
        config = load_config(args.config)
        
        # Pass relevant sections to components
        coordinator_config = config["coordinator"]
        system_config = config["system"]
        
        coordinator = Coordinator(coordinator_config, system_config)
        await coordinator.start()

    async def register_node(self, request):
        if request.headers.get("X-API-Key") != API_KEY:
            return web.Response(status=401)
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
            await redis.push('task_queue', json.dumps(task))  # Store in Redis for persistence
 
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
    
    async def cleanup_stale_nodes(self):
    while True:
        await asyncio.sleep(60)
        now = datetime.now()
        stale = []
        async with self.lock:
            for node_id, info in self.nodes.items():
                last = datetime.fromisoformat(info["last_heartbeat"])
                if (now - last).total_seconds() > 120:  # 2 minutes
                    stale.append(node_id)
            for node_id in stale:
                del self.nodes[node_id]
                logging.warning(f"Node {node_id} removed (stale)")


    async def submit_scan_api(self, request):
    data = await request.json()
    target = data["target"]
    scan_type = data.get("type", "comprehensive")
    task_id = await self.submit_scan(target, scan_type)
    return web.json_response({"task_id": task_id})

    async def get_task_status(self, request):
        task_id = request.match_info["task_id"]
        task = self.pending_tasks.get(task_id)
        if not task:
            return web.json_response({"error": "not found"}, status=404)
        status = "completed" if "result" in task else "pending"
            return web.json_response({"task_id": task_id, "status": status})

    async def get_result(self, request):
        task_id = request.match_info["task_id"]
        task = self.pending_tasks.get(task_id)
        if task and "result" in task:
            return web.json_response(task["result"])
        return web.json_response({"error": "not found"}, status=404)

    async def health(request):
        return web.Response(status=200)

    async def ready(request):
        # Check database connection, last heartbeat, etc.
        if coordinator.db_healthy and len(coordinator.nodes) > 0:
            return web.Response(status=200)
        return web.Response(status=503)


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
        asyncio.create_task(self.cleanup_stale_nodes())
    

    async def shutdown(sig, loop):
        logging.info(f"Received exit signal {sig.name}")
        # Cancel all background tasks
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        [t.cancel() for t in tasks]
        await asyncio.gather(*tasks, return_exceptions=True)
        loop.stop()

        loop = asyncio.get_event_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, lambda: asyncio.create_task(shutdown(sig, loop)))
        
        # Register
app.router.add_post("/scan", self.submit_scan_api)
app.router.add_get("/status/{task_id}", self.get_task_status)
app.router.add_get("/result/{task_id}", self.get_result)
app.router.add_get("/health", self.health)
app.router.add_get("/ready", self.ready)