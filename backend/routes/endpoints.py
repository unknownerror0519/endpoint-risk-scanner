from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from dateutil import parser as dtparser
from fastapi import APIRouter, HTTPException, Query

from backend.firestore_service import firestore_endpoints_from_env, firestore_scans_from_env
from backend.models import EndpointListItem, EndpointResults
from backend.azure_blob import download_blob_json


router = APIRouter(prefix="/endpoints", tags=["endpoints"])

# Agents send heartbeat roughly every 3 minutes.
# Use a slightly larger threshold to tolerate clock skew and transient delays.
ONLINE_THRESHOLD = timedelta(minutes=7)
_ROOT = Path(__file__).resolve().parents[2]  # project root


def _parse_dt(value: Any) -> Optional[datetime]:
    # Firestore timestamps typically come back as datetime.
    return value if isinstance(value, datetime) else None


def _is_online(last_seen_raw: Any) -> bool:
    """Return True if the device reported within the online threshold window."""
    if not last_seen_raw:
        return False
    try:
        if isinstance(last_seen_raw, datetime):
            ts = last_seen_raw if last_seen_raw.tzinfo else last_seen_raw.replace(tzinfo=timezone.utc)
        else:
            ts = dtparser.parse(str(last_seen_raw))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - ts) < ONLINE_THRESHOLD
    except (ValueError, TypeError):
        return False


@router.get("", response_model=List[EndpointListItem])
def list_endpoints(limit: int = Query(default=200, ge=1, le=1000)):
    endpoints_fs = firestore_endpoints_from_env()
    scans_fs = firestore_scans_from_env()
    docs = endpoints_fs.list_endpoints(limit=limit)

    items: List[EndpointListItem] = []
    for d in docs:
        endpoint_id = str(d.get("endpoint_id"))

        # Scan status/results are stored separately to avoid polluting the agent collection.
        scan_doc: Dict[str, Any] = {}
        try:
            scan_doc = scans_fs.get_endpoint(endpoint_id)
        except KeyError:
            scan_doc = {}

        conn = d.get("connection_status") or {}
        system = d.get("system") or {}
        identity = d.get("identity") or {}
        apps = d.get("applications") or []
        hostname = identity.get("hostname") or conn.get("hostname")
        last_seen_val = conn.get("last_seen")
        items.append(
            EndpointListItem(
                endpoint_id=endpoint_id,
                endpoint_name=hostname or d.get("endpoint_name") or d.get("name"),
                scan_status=scan_doc.get("scan_status") or "not_scanned",
                last_scanned_at=_parse_dt(scan_doc.get("last_scanned_at")),
                endpoint_risk_score_0_100=scan_doc.get("endpoint_risk_score_0_100"),
                endpoint_risk_tier=scan_doc.get("endpoint_risk_tier"),
                os_name=system.get("os_name"),
                is_online=_is_online(last_seen_val),
                last_seen=last_seen_val,
                application_count=len(apps),
            )
        )

    return items


@router.get("/{endpoint_id}", response_model=Dict[str, Any])
def get_endpoint(endpoint_id: str):
    fs = firestore_endpoints_from_env()
    try:
        doc: Dict[str, Any] = fs.get_endpoint(endpoint_id)

        # Normalize/compute live connection status.
        # Agents may report `connection_status.online=true` but never flip it back;
        # the API should compute online state from the most recent heartbeat.
        conn = doc.get("connection_status")
        if not isinstance(conn, dict):
            conn = {}
            doc["connection_status"] = conn

        last_seen_val = conn.get("last_seen")
        conn["online"] = _is_online(last_seen_val)

        return doc
    except KeyError:
        raise HTTPException(status_code=404, detail="Endpoint not found")


@router.get("/{endpoint_id}/results", response_model=EndpointResults)
def get_results(endpoint_id: str):
    endpoints_fs = firestore_endpoints_from_env()
    scans_fs = firestore_scans_from_env()
    try:
        endpoints_fs.get_endpoint(endpoint_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    try:
        doc = scans_fs.get_endpoint(endpoint_id)
    except KeyError:
        doc = {}

    return EndpointResults(
        endpoint_id=endpoint_id,
        scan_status=doc.get("scan_status") or "not_scanned",
        last_scanned_at=_parse_dt(doc.get("last_scanned_at")),
        endpoint_summary=doc.get("latest_endpoint_summary"),
        application_summaries=doc.get("application_summaries") or [],
        error_message=doc.get("scan_error_message"),
    )


@router.get("/{endpoint_id}/cves/{product_name}")
def get_cves_for_product(endpoint_id: str, product_name: str):
    """Return the list of matched CVEs for a specific application from the latest scan."""
    endpoints_fs = firestore_endpoints_from_env()
    scans_fs = firestore_scans_from_env()
    try:
        endpoints_fs.get_endpoint(endpoint_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Endpoint not found")

    try:
        doc = scans_fs.get_endpoint(endpoint_id)
    except KeyError:
        doc = {}

    artifacts = doc.get("latest_scan_artifacts") or {}

    scored_blob = artifacts.get("scored_blob") or {}
    if isinstance(scored_blob, dict) and scored_blob.get("account") and scored_blob.get("container") and scored_blob.get("blob"):
        try:
            data = download_blob_json(
                account_name=str(scored_blob["account"]),
                container_name=str(scored_blob["container"]),
                blob_name=str(scored_blob["blob"]),
            )
        except Exception as e:
            raise HTTPException(
                status_code=502,
                detail=(
                    "Failed to load scan results artifact from blob storage. "
                    f"Error: {type(e).__name__}: {e}"
                ),
            )
    else:
        scored_path_str = artifacts.get("scored")
        if not scored_path_str:
            raise HTTPException(status_code=404, detail="No scan results available")

        scored_path = _ROOT / Path(str(scored_path_str))
        if not scored_path.is_file():
            raise HTTPException(status_code=404, detail="Scan results file not found")

        data = json.loads(scored_path.read_text(encoding="utf-8"))

    for app in data:
        if app.get("display_product") == product_name:
            return {
                "display_product": app.get("display_product"),
                "vendor_normalized": app.get("vendor_normalized"),
                "product_normalized": app.get("product_normalized"),
                "version_normalized": app.get("version_normalized"),
                "matched_cve_count": app.get("matched_cve_count", 0),
                "matched_cves": app.get("matched_cves", []),
            }

    raise HTTPException(status_code=404, detail=f"Application '{product_name}' not found in scan results")
