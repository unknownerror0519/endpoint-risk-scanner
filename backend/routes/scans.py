from __future__ import annotations

import threading
from typing import Literal, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query

from backend.firestore_service import firestore_endpoints_from_env, firestore_scans_from_env
from backend.models import ScanStartResponse, ScanCancelResponse
from backend.scan_runner import run_scan_for_endpoint, cancel_scan


router = APIRouter(prefix="/endpoints", tags=["scans"])


_scan_lock = threading.Lock()
_scanning: set[str] = set()


def _scan_task(endpoint_id: str, endpoint_platform: Optional[str]) -> None:
    endpoints_fs = firestore_endpoints_from_env()
    scans_fs = firestore_scans_from_env()
    try:
        run_scan_for_endpoint(
            endpoints_fs,
            scans_fs,
            endpoint_id,
            endpoint_platform=endpoint_platform,
        )
    finally:
        with _scan_lock:
            _scanning.discard(endpoint_id)


@router.post("/{endpoint_id}/scan", response_model=ScanStartResponse)
def start_scan(
    endpoint_id: str,
    background: BackgroundTasks,
    endpoint_platform: Optional[Literal["windows", "macos", "linux", "unknown"]] = Query(
        default=None,
        description="Optional override for platform filtering during CVE mapping",
    ),
):
    endpoints_fs = firestore_endpoints_from_env()
    scans_fs = firestore_scans_from_env()
    try:
        endpoints_fs.get_endpoint(endpoint_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    # Prevent duplicate scans for the same endpoint.
    with _scan_lock:
        if endpoint_id in _scanning:
            raise HTTPException(status_code=409, detail="Scan already running for this endpoint")
        _scanning.add(endpoint_id)

    # Record status in scan-results collection (do not touch agent endpoint docs).
    # This also implicitly creates the scan-results collection/doc in Firestore.
    try:
        scans_fs.update_scan_status(
            endpoint_id,
            status="scanning",
            error_message=None,
        )
    except Exception as e:
        with _scan_lock:
            _scanning.discard(endpoint_id)
        raise HTTPException(
            status_code=500,
            detail=(
                "Failed to write scan status to the scan-results Firestore collection. "
                "Check FIRESTORE_SCAN_COLLECTION and IAM permissions. "
                f"Error: {type(e).__name__}: {e}"
            ),
        )

    # Schedule scan in background.
    background.add_task(_scan_task, endpoint_id, endpoint_platform)

    return ScanStartResponse(endpoint_id=endpoint_id, scan_status="scanning", message="Scan started")


@router.post("/{endpoint_id}/cancel", response_model=ScanCancelResponse)
def cancel_endpoint_scan(endpoint_id: str):
    endpoints_fs = firestore_endpoints_from_env()
    scans_fs = firestore_scans_from_env()
    try:
        endpoints_fs.get_endpoint(endpoint_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    with _scan_lock:
        is_tracked = endpoint_id in _scanning

    if not is_tracked:
        raise HTTPException(status_code=409, detail="No scan is running for this endpoint")

    killed = cancel_scan(endpoint_id)

    if killed:
        # _scan_task's finally block will discard from _scanning once the thread finishes
        scans_fs.update_scan_status(endpoint_id, status="failed", error_message="Scan was cancelled by user")
        return ScanCancelResponse(endpoint_id=endpoint_id, cancelled=True, message="Scan cancelled")

    return ScanCancelResponse(endpoint_id=endpoint_id, cancelled=False, message="Scan process not found — it may have already finished")
