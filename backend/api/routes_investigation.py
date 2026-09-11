from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.core.database import get_db
from backend.models import Investigation, InvestigationStep
from backend.schemas.investigation import (
    InvestigationResponse,
    InvestigationStepResponse,
    ToolExecutionRequest,
    ToolExecutionResponse,
)
from backend.ai.investigator import AIInvestigator
from backend.ai.tools import ForensicsToolRegistry

router = APIRouter(prefix="/investigation", tags=["Investigation"])


@router.get("/{incident_id}", response_model=InvestigationResponse)
def get_investigation(incident_id: str, db: Session = Depends(get_db)):
    inv = db.query(Investigation).filter(Investigation.incident_id == incident_id).first()
    if not inv:
        # Auto-initialize investigation
        ai = AIInvestigator(db)
        inv = ai.run_investigation(incident_id)

    steps = (
        db.query(InvestigationStep)
        .filter(InvestigationStep.investigation_id == inv.id)
        .order_by(InvestigationStep.step_number.asc())
        .all()
    )

    return InvestigationResponse(
        id=inv.id,
        incident_id=inv.incident_id,
        status=inv.status,
        started_at=inv.started_at,
        completed_at=inv.completed_at,
        trigger=inv.trigger,
        current_focus=inv.current_focus,
        steps=[
            InvestigationStepResponse(
                id=s.id,
                step_number=s.step_number,
                question=s.question,
                tool_called=s.tool_called,
                tool_parameters_json=s.tool_parameters_json,
                tool_result_json=s.tool_result_json,
                findings=s.findings,
                evidence_generated_ids=s.evidence_generated_ids,
            )
            for s in steps
        ],
    )


@router.post("/run/{incident_id}", response_model=InvestigationResponse)
def run_ai_investigation(incident_id: str, db: Session = Depends(get_db)):
    ai = AIInvestigator(db)
    inv = ai.run_investigation(incident_id)
    return get_investigation(incident_id, db)


@router.post("/tool-call", response_model=ToolExecutionResponse)
def execute_tool(req: ToolExecutionRequest, db: Session = Depends(get_db)):
    tools = ForensicsToolRegistry(db)
    fn = getattr(tools, req.tool_name, None)
    if not fn or not callable(fn):
        raise HTTPException(status_code=400, detail=f"Tool '{req.tool_name}' not supported")

    try:
        data = fn(**req.parameters)
        return ToolExecutionResponse(
            tool_name=req.tool_name,
            success=True,
            data=data,
            evidence_created=[],
        )
    except Exception as e:
        return ToolExecutionResponse(
            tool_name=req.tool_name,
            success=False,
            data=None,
            error=str(e),
        )
