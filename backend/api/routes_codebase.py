import os
import zipfile
import tempfile
import shutil
from typing import List, Optional
from pathlib import Path
from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from backend.core.database import get_db
from backend.ingestion.codebase_scanner import CodebaseScanner

router = APIRouter(prefix="/codebase", tags=["Codebase"])


class LocalScanRequest(BaseModel):
    path: str
    case_title: Optional[str] = None
    incident_id: Optional[str] = None


@router.post("/scan-local-path")
def scan_local_codebase_path(req: LocalScanRequest, db: Session = Depends(get_db)):
    """Scans an existing local directory on disk for services, configs, and telemetry."""
    if not os.path.exists(req.path):
        raise HTTPException(status_code=400, detail=f"Directory path '{req.path}' does not exist on disk.")

    if not os.path.isdir(req.path):
        raise HTTPException(status_code=400, detail=f"Path '{req.path}' is not a directory.")

    scanner = CodebaseScanner(db)
    result = scanner.process_extracted_folder(
        folder_path=req.path,
        case_title=req.case_title,
        incident_id=req.incident_id,
    )
    return {
        "status": "success",
        "data": result,
        "message": f"Successfully scanned codebase from '{req.path}' and extracted {len(result['services_discovered'])} services.",
    }


@router.post("/upload-folder")
async def upload_codebase_folder(
    files: List[UploadFile] = File(...),
    case_title: Optional[str] = Form(None),
    incident_id: Optional[str] = Form(None),
    db: Session = Depends(get_db),
):
    """Accepts uploaded files / directory tree (or zip archive) and runs forensic ingestion."""
    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded.")

    temp_dir = tempfile.mkdtemp(prefix="autopsy_upload_")
    try:
        # Check if single zip uploaded
        if len(files) == 1 and files[0].filename and files[0].filename.lower().endswith(".zip"):
            zip_dest = os.path.join(temp_dir, files[0].filename)
            with open(zip_dest, "wb") as buffer:
                shutil.copyfileobj(files[0].file, buffer)
            with zipfile.ZipFile(zip_dest, "r") as zip_ref:
                zip_ref.extractall(temp_dir)
            os.remove(zip_dest)
        else:
            # Multi-file folder tree upload
            for file in files:
                # filename might contain relative path if uploaded with webkitdirectory
                raw_name = file.filename or "unknown_file"
                # Normalize slashes
                rel_path = raw_name.replace("\\", "/").lstrip("/")
                dest_path = os.path.join(temp_dir, rel_path)
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                with open(dest_path, "wb") as buffer:
                    shutil.copyfileobj(file.file, buffer)

        # Run scanner on extracted directory
        scanner = CodebaseScanner(db)
        try:
            result = scanner.process_extracted_folder(
                folder_path=temp_dir,
                case_title=case_title,
                incident_id=incident_id,
            )
            return {
                "status": "success",
                "data": result,
                "message": f"Successfully ingested codebase. Discovered {len(result['services_discovered'])} services, {result['configs_extracted']} configs, and {result['logs_ingested']} log records.",
            }
        except Exception as e:
            db.rollback()
            raise HTTPException(status_code=500, detail=f"Codebase ingestion error: {str(e)}")
    finally:
        # Cleanup temporary files
        shutil.rmtree(temp_dir, ignore_errors=True)
