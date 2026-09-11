import os
import re
import json
import zipfile
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session

from backend.models import (
    Service,
    ServiceDependency,
    Incident,
    ConfigChange,
    Deployment,
    LogEntry,
    Evidence,
    Event,
)
from backend.models.base import generate_uuid, utc_now
from backend.ingestion import ingest_telemetry
from backend.anomaly.detector import AnomalyDetector
from backend.correlation.engine import CorrelationEngine
from backend.hypotheses.engine import HypothesisEngine
from backend.topology.blast_radius import BlastRadiusCalculator
from backend.normalization.normalizer import compute_fingerprint, normalize_timestamp


class CodebaseScanner:
    """Scans user-uploaded codebases, microservice folders, and configuration trees

    to extract service topology, configs, logs, and telemetry for forensic investigation.
    """

    def __init__(self, db: Session):
        self.db = db

    def process_extracted_folder(
        self,
        folder_path: str,
        case_title: Optional[str] = None,
        incident_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        p = Path(folder_path)
        folder_name = p.name or "uploaded-codebase"
        now = datetime.now(timezone.utc)

        # 1. Create Incident case file if not provided
        if not incident_id:
            incident = Incident(
                id=generate_uuid(),
                title=case_title or f"Forensic Case: {folder_name}",
                severity="SEV1",
                status="ACTIVE",
                started_at=now,
                summary=f"Incident case file generated from scanned codebase folder: '{folder_name}'.",
                is_simulated=False,
            )
            self.db.add(incident)
            self.db.flush()
            incident_id = incident.id
        else:
            incident = self.db.query(Incident).filter(Incident.id == incident_id).first()

        discovered_services: Dict[str, Service] = {}
        discovered_dependencies: List[Tuple[str, str, str]] = []
        discovered_configs: List[Dict[str, Any]] = []
        ingested_logs_count = 0

        # Known service markers
        service_indicators = {
            "package.json",
            "requirements.txt",
            "go.mod",
            "pom.xml",
            "Cargo.toml",
            "Dockerfile",
            "docker-compose.yml",
            "docker-compose.yaml",
        }

        # 2. Walk directory to discover services and configs
        for root, dirs, files in os.walk(folder_path):
            # Skip hidden/vendor directories
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules", "vendor", "__pycache__", "venv", ".git")]
            root_path = Path(root)
            rel_root = root_path.relative_to(p)

            # Check if this directory looks like a microservice
            service_files = set(files).intersection(service_indicators)
            if service_files and len(rel_root.parts) <= 3:
                # Name of service is the directory name
                svc_name = rel_root.name if rel_root.name and rel_root.name != "." else folder_name
                # Sanitize service name
                clean_name = re.sub(r"[^a-zA-Z0-9_-]", "-", svc_name).lower().strip("-")
                if clean_name and clean_name not in discovered_services:
                    tier = "tier-1" if any(w in clean_name for w in ("api", "gateway", "web", "frontend", "checkout", "auth")) else "tier-2"
                    if any(w in clean_name for w in ("db", "database", "postgres", "redis", "mysql", "mongo")):
                        tier = "tier-3"

                    svc = self.db.query(Service).filter(Service.name == clean_name).first()
                    if not svc:
                        svc = Service(
                            id=generate_uuid(),
                            name=clean_name,
                            tier=tier,
                            environment="production",
                            repo_url=f"local://{clean_name}",
                            oncall_team=f"team-{tier}",
                            metadata_json={"relative_path": str(rel_root)},
                        )
                        self.db.add(svc)
                        self.db.flush()
                    discovered_services[clean_name] = svc

            # Check for docker-compose files to extract explicit dependencies & topology
            for file in files:
                file_lower = file.lower()
                full_file_path = root_path / file

                # Parse Docker Compose for microservice topology
                if "docker-compose" in file_lower and (file_lower.endswith(".yml") or file_lower.endswith(".yaml")):
                    try:
                        self._parse_docker_compose(full_file_path, discovered_services, discovered_dependencies)
                    except Exception as e:
                        print(f"[CODEBASE SCANNER] Docker compose parse error in {file}: {e}")

                # Parse Config files (.env, .json, .yaml, .properties)
                if file_lower.endswith((".env", ".properties", ".ini", ".conf")) or (
                    file_lower.endswith((".json", ".yaml", ".yml")) and any(c in file_lower for c in ("config", "settings", "values", "app", "application"))
                ):
                    try:
                        cfgs = self._parse_config_file(full_file_path, discovered_services)
                        discovered_configs.extend(cfgs)
                    except Exception as e:
                        print(f"[CODEBASE SCANNER] Config parse error in {file}: {e}")

                # Ingest Log and Telemetry files (.log, .jsonl, .txt, .ndjson)
                if file_lower.endswith((".log", ".jsonl", ".ndjson")) or ("telemetry" in str(rel_root).lower() and file_lower.endswith(".json")):
                    try:
                        count = self._ingest_log_file(full_file_path, incident_id, discovered_services)
                        ingested_logs_count += count
                    except Exception as e:
                        print(f"[CODEBASE SCANNER] Log ingest error in {file}: {e}")

        # If no explicit services found, create at least a root service for the codebase
        if not discovered_services:
            root_svc_name = re.sub(r"[^a-zA-Z0-9_-]", "-", folder_name).lower()
            svc = self.db.query(Service).filter(Service.name == root_svc_name).first()
            if not svc:
                svc = Service(
                    id=generate_uuid(),
                    name=root_svc_name,
                    tier="tier-1",
                    environment="production",
                    repo_url=f"local://{folder_name}",
                    oncall_team="team-tier-1",
                )
                self.db.add(svc)
                self.db.flush()
            discovered_services[root_svc_name] = svc

        # 3. Create Service Dependencies
        for src_name, tgt_name, dep_type in discovered_dependencies:
            src = discovered_services.get(src_name)
            tgt = discovered_services.get(tgt_name)
            if src and tgt and src.id != tgt.id:
                existing = (
                    self.db.query(ServiceDependency)
                    .filter(
                        ServiceDependency.source_service_id == src.id,
                        ServiceDependency.target_service_id == tgt.id,
                    )
                    .first()
                )
                if not existing:
                    dep = ServiceDependency(
                        id=generate_uuid(),
                        source_service_id=src.id,
                        target_service_id=tgt.id,
                        dependency_type=dep_type,
                        is_critical=True,
                        avg_latency_ms=15.0,
                    )
                    self.db.add(dep)

        # 4. Save Config Changes found
        cfg_counter = self.db.query(Evidence).filter(Evidence.incident_id == incident_id).count()
        for cfg in discovered_configs:
            svc_name = cfg.get("service") or list(discovered_services.keys())[0]
            cc = ConfigChange(
                id=generate_uuid(),
                service=svc_name,
                config_key=cfg.get("key", "unknown_key"),
                old_value=str(cfg.get("old_value", "")),
                new_value=str(cfg.get("new_value", "")),
                changed_at=now,
                changed_by="codebase-upload",
                reason=f"Extracted from {cfg.get('file', 'config file')}",
                environment="production",
            )
            self.db.add(cc)

            # Generate evidence for critical configuration items
            import uuid
            cfg_counter += 1
            ev = Evidence(
                id=f"EVID-CODE-CFG-{cfg_counter:04d}-{uuid.uuid4().hex[:6].upper()}",
                incident_id=incident_id,
                timestamp=now,
                evidence_type="CONFIG",
                source=f"codebase:{cfg.get('file')}",
                entity=f"{svc_name}.{cfg.get('key')}",
                content=cfg,
                confidence=1.0,
                provenance={"source_file": cfg.get("file"), "scanner": "CodebaseScanner"},
            )
            self.db.add(ev)

        self.db.commit()

        # 5. Run forensics over newly ingested codebase data
        if incident:
            detector = AnomalyDetector(self.db)
            detector.analyze_incident_metrics(incident_id)

            correlator = CorrelationEngine(self.db)
            correlator.correlate_incident_events(incident_id)

            hyp_engine = HypothesisEngine(self.db)
            hyp_engine.generate_competing_hypotheses(incident_id)

        return {
            "incident_id": incident_id,
            "folder_name": folder_name,
            "services_discovered": list(discovered_services.keys()),
            "dependencies_count": len(discovered_dependencies),
            "configs_extracted": len(discovered_configs),
            "logs_ingested": ingested_logs_count,
        }

    def _parse_docker_compose(
        self,
        file_path: Path,
        discovered_services: Dict[str, Service],
        discovered_dependencies: List[Tuple[str, str, str]],
    ):
        """Extracts services and inter-service dependencies from Docker Compose."""
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        # Lightweight regex parsing of service definitions and depends_on
        lines = content.splitlines()
        current_service = None
        in_services_block = False
        in_depends_on = False

        for line in lines:
            indent = len(line) - len(line.lstrip())
            stripped = line.strip()

            if stripped.startswith("services:"):
                in_services_block = True
                continue

            if in_services_block:
                # Service level indent is typically 2 spaces
                if indent == 2 and stripped.endswith(":") and not stripped.startswith("-"):
                    current_service = stripped[:-1].strip().lower()
                    in_depends_on = False
                    if current_service and current_service not in discovered_services:
                        tier = "tier-1" if any(w in current_service for w in ("api", "gateway", "web", "frontend", "checkout")) else "tier-2"
                        if any(w in current_service for w in ("db", "postgres", "redis", "mysql")):
                            tier = "tier-3"
                        svc = self.db.query(Service).filter(Service.name == current_service).first()
                        if not svc:
                            svc = Service(
                                id=generate_uuid(),
                                name=current_service,
                                tier=tier,
                                environment="production",
                                repo_url=f"compose://{current_service}",
                                oncall_team=f"team-{tier}",
                            )
                            self.db.add(svc)
                            self.db.flush()
                        discovered_services[current_service] = svc
                    continue

                if current_service:
                    if stripped.startswith("depends_on:"):
                        in_depends_on = True
                        continue

                    if in_depends_on:
                        if stripped.startswith("- "):
                            dep_target = stripped[2:].strip().lower()
                            discovered_dependencies.append((current_service, dep_target, "RPC"))
                        elif indent <= 4 and stripped.endswith(":") and not stripped.startswith("-"):
                            # Next property in service block
                            in_depends_on = False

                    # Check for environment variables linking other services (e.g. PAYMENT_SERVICE_URL=http://payment-service:8080)
                    if any(kw in stripped for kw in ("_URL=", "_HOST=", "_ADDR=", "URI=")):
                        for candidate in discovered_services.keys():
                            if candidate != current_service and candidate in stripped.lower():
                                dtype = "DB" if "db" in candidate or "postgres" in candidate or "mysql" in candidate else "RPC"
                                discovered_dependencies.append((current_service, candidate, dtype))

    def _parse_config_file(
        self,
        file_path: Path,
        discovered_services: Dict[str, Service],
    ) -> List[Dict[str, Any]]:
        """Extracts configuration settings like pool sizes, timeouts, limits."""
        cfgs = []
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        filename = file_path.name

        # Detect service owner from parent directory or file path
        service_owner = None
        for part in file_path.parts:
            if part.lower() in discovered_services:
                service_owner = part.lower()
                break

        # Check for key configuration patterns
        patterns = [
            (r"((?:[a-zA-Z0-9_.-]+\.)?pool[._-]?(?:size|max|connections?|capacity))\s*[:=]\s*([0-9]+)", "pool_size"),
            (r"((?:[a-zA-Z0-9_.-]+\.)?timeout[._-]?(?:ms|sec|seconds)?)\s*[:=]\s*([0-9]+)", "timeout"),
            (r"((?:[a-zA-Z0-9_.-]+\.)?(?:threads?|workers?|max[._-]threads?))\s*[:=]\s*([0-9]+)", "thread_limit"),
            (r"((?:[a-zA-Z0-9_.-]+\.)?(?:retries?|max[._-]retries?))\s*[:=]\s*([0-9]+)", "retry_limit"),
        ]

        for pat, cat in patterns:
            for match in re.finditer(pat, content, re.IGNORECASE):
                key = match.group(1).strip()
                val = match.group(2).strip()
                cfgs.append({
                    "service": service_owner,
                    "key": key,
                    "new_value": val,
                    "old_value": "default",
                    "category": cat,
                    "file": filename,
                })
        return cfgs

    def _ingest_log_file(
        self,
        file_path: Path,
        incident_id: str,
        discovered_services: Dict[str, Service],
    ) -> int:
        """Parses lines of log files, extracts levels, timestamps, messages."""
        lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        count = 0
        service_owner = None
        for part in file_path.parts:
            if part.lower() in discovered_services:
                service_owner = part.lower()
                break
        if not service_owner:
            service_owner = list(discovered_services.keys())[0] if discovered_services else "application"

        for line in lines[:500]:  # Cap at 500 lines per file for ingestion speed
            stripped = line.strip()
            if not stripped:
                continue

            level = "INFO"
            if any(w in stripped.upper() for w in ("ERROR", "FATAL", "PANIC", "CRITICAL")):
                level = "ERROR"
            elif any(w in stripped.upper() for w in ("WARN", "WARNING")):
                level = "WARN"

            # Check if JSON
            log_data = {"service": service_owner, "message": stripped, "level": level}
            if stripped.startswith("{") and stripped.endswith("}"):
                try:
                    parsed = json.loads(stripped)
                    log_data.update(parsed)
                    if "level" not in parsed:
                        log_data["level"] = level
                except Exception:
                    pass

            try:
                ingest_telemetry(
                    db=self.db,
                    source_type="LOG",
                    payload=log_data,
                    incident_id=incident_id,
                    source=f"file:{file_path.name}",
                )
                count += 1
            except Exception as e:
                self.db.rollback()
                print(f"[CODEBASE SCANNER] Warning: skipped problematic log entry in {file_path.name}: {e}")

        try:
            self.db.commit()
        except Exception as e:
            self.db.rollback()
            print(f"[CODEBASE SCANNER] Commit warning in {file_path.name}: {e}")

        return count
