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
        self.config = config
        self.scanner = AdvancedScanner(config["scanning"],
         MLReconEngine(config.get("ml", {})),
          ThreatIntelligence(config.get("threat_intel", {})))  # instantiate your scanner
        self.session = None

    async def main():
        parser = argparse.ArgumentParser()
        parser.add_argument("-c", "--config", default="config.yaml")
        parser.add_argument("--id", required=True)
        parser.add_argument("--coordinator", required=True)
        args = parser.parse_args()
        
        config = load_config(args.config)   # from config.py
        worker = Worker(args.id, args.coordinator, config["worker"]["capabilities"], config)
    await worker.start()

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
                _, task_data = await redis.blpop("task_queue", timeout=5)
                if task_data:
                    task = json.loads(task_data)
                    result = await execute_task(task)
                    await redis.publish("results", json.dumps({"task_id": task["id"], "result": result}))
                    
            await asyncio.sleep(1)  # poll interval

    async def health(request):
        return web.Response(status=200)

    async def ready(request):
        # Check database connection, last heartbeat, etc.
        if coordinator.db_healthy and len(coordinator.nodes) > 0:
            return web.Response(status=200)
        return web.Response(status=503)


    async def execute_task(self, task: dict):
        target = task["target"]
        scan_type = task["type"]
        if scan_type == "comprehensive":
            return await self.scanner.comprehensive_scan(target)
        else:
            return {"error": "unknown type"}

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


app.router.add_post("/scan", self.submit_scan_api)
app.router.add_get("/status/{task_id}", self.get_task_status)
app.router.add_get("/result/{task_id}", self.get_result)
app.router.add_get("/health", self.health)
app.router.add_get("/ready", self.ready)