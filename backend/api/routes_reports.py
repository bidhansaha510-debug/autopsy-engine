from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from backend.core.database import get_db
from backend.models import Report
from backend.schemas.investigation import ReportResponse, ReportUpdateRequest
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


@router.put("/{report_id}", response_model=ReportResponse)
def update_report(
    report_id: str,
    update_data: "ReportUpdateRequest",
    db: Session = Depends(get_db),
):
    rep = db.query(Report).filter(Report.id == report_id).first()
    if not rep:
        raise HTTPException(status_code=404, detail="Report not found")

    if update_data.title is not None:
        rep.title = update_data.title
    if update_data.content_markdown is not None:
        rep.content_markdown = update_data.content_markdown
    if update_data.executive_summary is not None:
        rep.executive_summary = update_data.executive_summary
    if update_data.rca_statement is not None:
        rep.rca_statement = update_data.rca_statement
    if update_data.recommendations is not None:
        rep.recommendations = update_data.recommendations
    if update_data.preventive_actions is not None:
        rep.preventive_actions = update_data.preventive_actions

    db.commit()
    db.refresh(rep)
    return rep
