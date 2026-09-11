import pytest
from datetime import datetime, timezone, timedelta
from backend.core.database import SessionLocal, init_db
from backend.models import Incident, Report
from backend.connectors.manager import StackPullManager
from backend.reports.generator import ForensicReportGenerator
from backend.schemas.investigation import ReportUpdateRequest
from backend.api.routes_reports import update_report


@pytest.fixture(scope="module")
def db_session():
    init_db()
    session = SessionLocal()
    yield session
    session.close()


def test_stack_pull_manager_orchestration(db_session):
    """Tests pulling telemetry from Prometheus, Kubernetes, and Git connectors."""
    manager = StackPullManager(db_session)
    result = manager.pull_stack_telemetry(
        lookback_hours=2.0,
        case_title="Test Stack Telemetry Outage",
        providers=["prometheus", "kubernetes", "git"],
        services=["payment-service", "checkout-service", "api-gateway"],
    )

    assert result is not None
    assert "incident_id" in result
    assert result["anomalies_detected"] >= 1
    assert result["correlations_linked"] >= 1
    assert result["hypotheses_count"] >= 1
    assert "prometheus" in result["providers_queried"]
    assert "kubernetes" in result["providers_queried"]
    assert "git" in result["providers_queried"]
    assert result["leading_hypothesis"] is not None
    assert result["report_id"] is not None


def test_dynamic_report_recommendations(db_session):
    """Verifies that report recommendations and preventive actions are dynamically generated."""
    # Find an incident or create one
    inc = db_session.query(Incident).first()
    assert inc is not None

    gen = ForensicReportGenerator(db_session)
    report = gen.generate_incident_report(inc.id)

    assert report is not None
    assert len(report.recommendations) >= 2
    assert len(report.preventive_actions) >= 1
    # Check that recommendations mention specific services or actions
    rec_text = " ".join([r["action"] for r in report.recommendations])
    assert any(term in rec_text.lower() for term in ["circuit breaker", "validation", "canary", "autoscaling", "rollback"])


def test_report_update_persistence(db_session):
    """Verifies that post-mortem report edits are persisted to the database via update_report."""
    report = db_session.query(Report).first()
    assert report is not None

    original_md = report.content_markdown
    new_md = original_md + "\n\n## 8. SRE Team Incident Review Notes\n- Verified by on-call commander Shay.\n- Action item assigned to DevOps team."

    req = ReportUpdateRequest(
        content_markdown=new_md,
        title="Updated Post-Mortem Report Title",
    )

    updated = update_report(report_id=report.id, update_data=req, db=db_session)
    assert updated.title == "Updated Post-Mortem Report Title"
    assert "SRE Team Incident Review Notes" in updated.content_markdown

    # Query afresh from DB
    reloaded = db_session.query(Report).filter(Report.id == report.id).first()
    assert reloaded.title == "Updated Post-Mortem Report Title"
    assert "SRE Team Incident Review Notes" in reloaded.content_markdown
