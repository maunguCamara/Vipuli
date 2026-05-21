# worker.py
import asyncio
import aiohttp
import logging
from scanner_core import AdvancedScanner, MLReconEngine, ThreatIntelligence   # your scanning logic

class Worker:
    def __init__(self, node_id: str, coordinator_url: str, capabilities: list, config: dict):
        self.node_id = node_id
        self.coordinator_url = coordinator_url
        self.capabilities = capabilities
        self.current_load = 0
        self.scanner = AdvancedScanner(config, MLReconEngine(), ThreatIntelligence())  # instantiate your scanner
        self.session = None

    async def start(self):
        await self.ml_engine.load_models()  # Load ML models before registering
        self.session = aiohttp.ClientSession()
        await self.register()
        asyncio.create_task(self.heartbeat_loop())
        asyncio.create_task(self.task_polling_loop())
        # Keep running
        await asyncio.Event().wait()

    async def register(self):
        data = {
            "node_id": self.node_id,
            "ip": "192.168.1.100",   # actual IP
            "port": 9000,
            "capabilities": self.capabilities,
            "load": self.current_load
        }
        async with self.session.post(f"{self.coordinator_url}/register", json=data) as resp:
            logging.info(f"Registration response: {resp.status}")

    async def heartbeat_loop(self):
        while True:
            await asyncio.sleep(30)
            data = {"node_id": self.node_id, "load": self.current_load}
            async with self.session.post(f"{self.coordinator_url}/heartbeat", json=data):
                pass

    async def task_polling_loop(self):
        while True:
            async with self.session.get(f"{self.coordinator_url}/task") as resp:
                task_data = await resp.json()
                task = task_data.get("task")
                if task:
                    # Execute task
                    self.current_load += 1
                    result = await self.execute_task(task)
                    # Send result back
                    await self.session.post(f"{self.coordinator_url}/result", json={
                        "task_id": task["task_id"],
                        "result": result
                    })
                    self.current_load -= 1
            await asyncio.sleep(1)  # poll interval

    async def execute_task(self, task: dict):
        target = task["target"]
        scan_type = task["type"]
        if scan_type == "comprehensive":
            return await self.scanner.comprehensive_scan(target)
        else:
            return {"error": "unknown type"}