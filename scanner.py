# ---------- Advanced Scanner (Real async scanning) ----------
class AdvancedScanner:
    def __init__(self, config: Dict, ml_engine: MLReconEngine, threat_intel: ThreatIntelligence):
        self.config = config
        self.ml = ml_engine
        self.threat_intel = threat_intel
        self.scan_history = {}
        self.active_scans: Dict[str, asyncio.Task] = {}
        self.semaphore = asyncio.Semaphore(config["scanning"]["port_scan_concurrency"])

    async def comprehensive_scan(self, target: str) -> Dict:
        scan_id = str(uuid.uuid4())
        start = datetime.now()
        logging.info(f"Starting comprehensive scan {scan_id} for {target}")
        results = {"scan_id": scan_id, "target": target, "start_time": start.isoformat(), "phases": {}}
        try:
            # Phase 1: Threat intelligence
            results["phases"]["threat_intel"] = await self.threat_intel.enrich_target(target)
            # Phase 2: Subdomain discovery (ML)
            results["phases"]["subdomains"] = await self._discover_subdomains(target)
            # Phase 3: Port scanning
            results["phases"]["port_scan"] = await self._port_scan(target)
            # Phase 4: Service detection on open ports
            open_ports = [p["port"] for p in results["phases"]["port_scan"].get("open_ports", [])]
            results["phases"]["services"] = await self._detect_services(target, open_ports)
            # Phase 5: Vulnerability classification
            results["phases"]["vuln_assessment"] = await self._assess_vulnerabilities(results["phases"]["services"])
            # Phase 6: Traffic analysis (dummy for now)
            results["phases"]["traffic"] = await self._analyze_traffic(target)
            # Phase 7: Anomaly detection
            results["phases"]["anomalies"] = await self._detect_anomalies(target)
        except Exception as e:
            logging.exception(f"Scan {scan_id} failed")
            results["error"] = str(e)
        results["end_time"] = datetime.now().isoformat()
        results["duration"] = (datetime.now() - start).total_seconds()
        return results

    async def _discover_subdomains(self, domain: str) -> Dict:
        predicted = await self.ml.predict_subdomains(domain)
        validated = []
        # Actually resolve subdomains using DNS
        for sub in predicted:
            try:
                await asyncio.get_running_loop().getaddrinfo(sub, 80)
                validated.append({"subdomain": sub, "active": True})
            except:
                pass
        return {"predicted": len(predicted), "validated": len(validated), "subdomains": validated}

    async def _port_scan(self, target: str) -> Dict:
        """Real TCP connect scan with adaptive concurrency."""
        common_ports = self.config["scanning"]["common_ports"]
        timeout = self.config["scanning"]["connect_timeout"]
        open_ports = []
        sem = self.semaphore

        async def scan_one(port: int):
            async with sem:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(target, port),
                        timeout=timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    return port
                except:
                    return None

        tasks = [scan_one(p) for p in common_ports]
        results = await asyncio.gather(*tasks)
        for port in results:
            if port is not None:
                open_ports.append({"port": port, "state": "open"})
        return {"scanned_ports": len(common_ports), "open_ports": len(open_ports), "ports": open_ports}

    async def _detect_services(self, target: str, ports: List[int]) -> Dict:
        """Banner grabbing for open ports."""
        services = []
        for port in ports:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port),
                    timeout=3.0
                )
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                await writer.drain()
                banner = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                writer.close()
                # Simple service guess
                service = "unknown"
                if b"SSH" in banner:
                    service = "ssh"
                elif b"HTTP" in banner:
                    service = "http"
                elif b"220" in banner:
                    service = "ftp"
                services.append({"port": port, "service": service, "banner": banner[:100].decode(errors="ignore")})
            except:
                services.append({"port": port, "service": "unknown", "banner": ""})
        return {"detected_services": len(services), "services": services}

    async def _assess_vulnerabilities(self, services: Dict) -> Dict:
        assessments = []
        for svc in services.get("services", []):
            vuln = await self.ml.classify_vulnerability(svc.get("service", "unknown"), "unknown_version")
            assessments.append({**svc, "vulnerability": vuln})
        return {"assessments": assessments}

    async def _analyze_traffic(self, target: str) -> Dict:
        # Dummy: in real system, would collect packet captures or netflow data
        return await self.ml.analyze_traffic([])

    async def _detect_anomalies(self, target: str) -> Dict:
        # Dummy: would compare current metrics against learned baseline
        current = {"response_time": 150, "packet_size": 500}
        baseline = {"response_time": 100, "packet_size": 512}
        anomalies = await self.ml.detect_anomalies(current, baseline)
        return {"anomalies": anomalies}
