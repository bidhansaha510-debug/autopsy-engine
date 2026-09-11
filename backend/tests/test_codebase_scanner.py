import os
import tempfile
import shutil
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.core.database import Base
from backend.ingestion.codebase_scanner import CodebaseScanner
from backend.models import Service, ServiceDependency, Incident, ConfigChange, LogEntry


@pytest.fixture
def test_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


def test_codebase_folder_scan(test_db):
    # Setup temporary multi-service project folder
    temp_dir = tempfile.mkdtemp(prefix="test_repo_")
    try:
        # Service 1: auth-service
        auth_dir = os.path.join(temp_dir, "auth-service")
        os.makedirs(auth_dir, exist_ok=True)
        with open(os.path.join(auth_dir, "package.json"), "w") as f:
            f.write('{"name": "auth-service", "version": "1.0.0"}')

        # Service 2: payment-service with config and logs
        payment_dir = os.path.join(temp_dir, "payment-service")
        os.makedirs(payment_dir, exist_ok=True)
        with open(os.path.join(payment_dir, "Dockerfile"), "w") as f:
            f.write("FROM python:3.11\nCMD python app.py")
        with open(os.path.join(payment_dir, "config.yaml"), "w") as f:
            f.write("database.pool.size: 5\ntimeout_ms: 3000\n")

        # Docker compose linking them
        compose_path = os.path.join(temp_dir, "docker-compose.yml")
        with open(compose_path, "w") as f:
            f.write("""
version: '3.8'
services:
  auth-service:
    image: auth:latest
  payment-service:
    image: payment:latest
    depends_on:
      - auth-service
""")

        # Log file
        logs_dir = os.path.join(payment_dir, "logs")
        os.makedirs(logs_dir, exist_ok=True)
        with open(os.path.join(logs_dir, "app.log"), "w") as f:
            f.write("2026-09-12 00:00:00 [ERROR] DB connection pool exhausted: 5/5 active\n")

        scanner = CodebaseScanner(test_db)
        res = scanner.process_extracted_folder(temp_dir, case_title="E2E Codebase Upload Test")

        assert res["incident_id"] is not None
        assert "auth-service" in res["services_discovered"]
        assert "payment-service" in res["services_discovered"]
        assert res["configs_extracted"] >= 1
        assert res["logs_ingested"] >= 1

        # Check DB records
        incident = test_db.query(Incident).filter(Incident.id == res["incident_id"]).first()
        assert incident is not None

        cfg = test_db.query(ConfigChange).filter(ConfigChange.config_key == "database.pool.size").first()
        assert cfg is not None
        assert cfg.new_value == "5"

        deps = test_db.query(ServiceDependency).all()
        assert len(deps) >= 1
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_codebase_scanner_with_many_error_logs(test_db):
    temp_dir = tempfile.mkdtemp(prefix="test_logs_repo_")
    try:
        service_dir = os.path.join(temp_dir, "aegiscyber-service")
        os.makedirs(service_dir, exist_ok=True)
        with open(os.path.join(service_dir, "package.json"), "w") as f:
            f.write('{"name": "aegiscyber"}')

        # Create multiple log files with repeated WARN/ERROR lines
        log1 = os.path.join(service_dir, "aegiscyber.jsonl")
        with open(log1, "w") as f:
            for i in range(25):
                f.write(f'{{"level": "WARNING", "message": "Ollama health check failed: Event loop is closed {i}", "timestamp": "2026-08-24T22:10:43Z"}}\n')

        log2 = os.path.join(service_dir, "audit.jsonl")
        with open(log2, "w") as f:
            for i in range(25):
                f.write(f'{{"level": "ERROR", "message": "Transaction failure in ledger block {i}", "timestamp": "2026-08-24T22:12:00Z"}}\n')

        scanner = CodebaseScanner(test_db)
        res = scanner.process_extracted_folder(temp_dir, case_title="Batch Error Log Stress Test")

        assert res["incident_id"] is not None
        assert res["logs_ingested"] >= 50

        # Verify all evidence items generated have unique IDs
        from backend.models import Evidence
        evidence_items = test_db.query(Evidence).filter(Evidence.incident_id == res["incident_id"]).all()
        ids = [e.id for e in evidence_items]
        assert len(ids) == len(set(ids))  # All IDs must be strictly unique!
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
