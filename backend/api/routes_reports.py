from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from backend.core.database import get_db
from backend.models import Report
from backend.schemas.investigation import ReportResponse
from backend.reports.generator import ForensicReportGenerator

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("/{incident_id}", response_model=ReportResponse)
def get_incident_report(incident_id: str, db: Session = Depends(get_db)):
    rep = (
        db.query(Report)
        .filter(Report.incident_id == incident_id)
        .order_by(Report.generated_at.desc())
        .first()
    )
    if not rep:
        # Generate initial report
        gen = ForensicReportGenerator(db)
        rep = gen.generate_incident_report(incident_id)
    return rep


@router.post("/generate/{incident_id}", response_model=ReportResponse)
def generate_fresh_report(incident_id: str, db: Session = Depends(get_db)):
    gen = ForensicReportGenerator(db)
    rep = gen.generate_incident_report(incident_id)
    return rep


@router.get("/export/{report_id}")
def export_report_markdown(report_id: str, db: Session = Depends(get_db)):
    rep = db.query(Report).filter(Report.id == report_id).first()
    if not rep:
        raise HTTPException(status_code=404, detail="Report not found")

    return Response(
        content=rep.content_markdown,
        media_type="text/markdown",
        headers={"Content-Disposition": f"attachment; filename=incident_autopsy_{report_id}.md"},
    )
