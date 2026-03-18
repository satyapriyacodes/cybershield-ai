"""
Logs router — ingest and store raw security logs.
"""

import os
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException
from sqlalchemy.orm import Session
from loguru import logger

from src.database.database import get_db
from src.database.models import LogEntry
from src.data.log_parser import parse_logs
from src.api.schemas import LogIngestRequest

router = APIRouter()


@router.post("/logs/ingest", summary="Upload and parse log file")
async def ingest_logs_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """Upload a CSV, JSON, or syslog file for processing."""
    filename = file.filename or "upload"
    ext = filename.rsplit(".", 1)[-1].lower()
    fmt = {"csv": "csv", "json": "json", "log": "syslog", "txt": "syslog"}.get(ext, "csv")

    content = (await file.read()).decode("utf-8", errors="replace")
    try:
        records = parse_logs(content, fmt)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Parse error: {e}")

    saved = 0
    for rec in records:
        entry = LogEntry(
            raw_log=str(rec),
            parsed_data=rec,
            timestamp=rec.get("timestamp"),
            user=rec.get("user"),
            ip_address=rec.get("ip_address"),
            action=rec.get("action"),
            status=rec.get("status"),
            location=rec.get("location"),
            device=rec.get("device"),
            processed=False,
        )
        db.add(entry)
        saved += 1

    db.commit()
    return {"saved": saved, "format": fmt, "filename": filename}


@router.post("/logs/ingest/text", summary="Ingest raw log text")
async def ingest_logs_text(body: LogIngestRequest, db: Session = Depends(get_db)):
    """Ingest raw log text string (for API clients)."""
    try:
        records = parse_logs(body.content, body.format)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Parse error: {e}")

    for rec in records:
        entry = LogEntry(
            raw_log=str(rec),
            parsed_data=rec,
            timestamp=rec.get("timestamp"),
            user=rec.get("user"),
            ip_address=rec.get("ip_address"),
            action=rec.get("action"),
            status=rec.get("status"),
            location=rec.get("location"),
            device=rec.get("device"),
            processed=False,
        )
        db.add(entry)

    db.commit()
    return {"saved": len(records), "format": body.format}
