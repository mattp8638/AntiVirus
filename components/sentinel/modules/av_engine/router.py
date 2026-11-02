from fastapi import APIRouter, HTTPException

from .models import AVScanRequest
from .scanner import engine_status, scan

router = APIRouter()


@router.get("/status")
def status():
    return engine_status()


@router.post("/scan")
def scan_native(request: AVScanRequest):
    try:
        return scan(request)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
