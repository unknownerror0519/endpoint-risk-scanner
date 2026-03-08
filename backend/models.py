from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


ScanStatus = Literal["not_scanned", "scanning", "completed", "failed"]


class EndpointListItem(BaseModel):
    endpoint_id: str = Field(..., description="Firestore document id")
    endpoint_name: Optional[str] = None

    scan_status: ScanStatus = "not_scanned"
    last_scanned_at: Optional[datetime] = None

    endpoint_risk_score_0_100: Optional[float] = None
    endpoint_risk_tier: Optional[str] = None

    os_name: Optional[str] = None
    is_online: Optional[bool] = None
    last_seen: Optional[str] = None
    application_count: int = 0


class ApplicationSummary(BaseModel):
    display_product: str
    vendor_normalized: Optional[str] = None
    product_normalized: Optional[str] = None
    version_normalized: Optional[str] = None

    matched_cve_count: int = 0

    application_risk_score_0_100: Optional[float] = None
    application_risk_tier: Optional[str] = None

    kev_cve_count: int = 0
    exploit_evidence_count: int = 0


class EndpointResults(BaseModel):
    endpoint_id: str
    scan_status: ScanStatus
    last_scanned_at: Optional[datetime] = None

    endpoint_summary: Optional[Dict[str, Any]] = None
    application_summaries: List[ApplicationSummary] = []

    error_message: Optional[str] = None


class ScanStartResponse(BaseModel):
    endpoint_id: str
    scan_status: ScanStatus
    message: str


class ScanCancelResponse(BaseModel):
    endpoint_id: str
    cancelled: bool
    message: str


class ErrorResponse(BaseModel):
    detail: Any
