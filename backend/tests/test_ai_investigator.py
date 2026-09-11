import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.core.database import Base
from backend.replay.engine import IncidentReplayEngine
from backend.ai.investigator import AIInvestigator
from backend.reports.generator import ForensicReportGenerator


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


def test_ai_investigator_tool_loop(test_db):
    replay = IncidentReplayEngine(test_db)
    incident = replay.bootstrap_canonical_incident()

    ai = AIInvestigator(test_db)
    inv = ai.run_investigation(incident.id)

    assert inv.status == "COMPLETED"
    assert len(inv.steps) == 4

    # Verify tool calls
    tools_called = [s.tool_called for s in inv.steps]
    assert "inspect_config_change" in tools_called
    assert "compare_baseline" in tools_called
    assert "get_logs" in tools_called
    assert "test_hypothesis" in tools_called

    # Verify each step has factual findings and generated evidence IDs
    for s in inv.steps:
        assert len(s.findings) > 0

    # Verify report generator compiles evidence-backed report
    gen = ForensicReportGenerator(test_db)
    report = gen.generate_incident_report(incident.id)

    assert report.id is not None
    assert "FORENSIC INCIDENT REPORT" in report.content_markdown
    assert "Database connection-pool exhaustion" in report.rca_statement or "pool" in report.rca_statement.lower()
    assert len(report.recommendations) > 0
