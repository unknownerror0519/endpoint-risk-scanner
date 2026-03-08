from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any, Dict, Optional

from backend.firestore_service import FirestoreService
from backend.bootstrap import ensure_nvd_dataset_present
from backend.azure_blob import upload_blob_from_path


ROOT = Path(__file__).resolve().parents[1]
ORCHESTRATOR = ROOT / "product" / "run_endpoint_scan.py"


def _get_artifacts_blob_config() -> Optional[dict]:
    account = os.getenv("SCAN_ARTIFACTS_AZURE_STORAGE_ACCOUNT")
    if not account:
        return None
    return {
        "account": account,
        "container": os.getenv("SCAN_ARTIFACTS_AZURE_CONTAINER") or "scan-artifacts",
        "prefix": (os.getenv("SCAN_ARTIFACTS_PREFIX") or "scans").strip("/"),
    }


def _extract_scan_dir_name(bundle: dict) -> Optional[str]:
    scan_dir = bundle.get("scan_dir")
    if not scan_dir:
        return None
    parts = str(scan_dir).replace("\\", "/").split("/")
    return parts[-1] if parts else None

# Track running subprocess handles so they can be cancelled.
_proc_lock = threading.Lock()
_running_procs: Dict[str, subprocess.Popen] = {}


def cancel_scan(endpoint_id: str) -> bool:
    """Kill the subprocess for a running scan. Returns True if killed."""
    with _proc_lock:
        proc = _running_procs.pop(endpoint_id, None)
    if proc is None:
        return False
    try:
        proc.kill()
        proc.wait(timeout=10)
    except Exception:
        pass
    return True


def _extract_bundle_path(stdout: str) -> Optional[str]:
    match = re.search(r"^Bundle:\s*(.+)\s*$", stdout, flags=re.MULTILINE)
    if not match:
        return None
    return match.group(1).strip()


def run_scan_for_endpoint(
    endpoints_store: FirestoreService,
    scans_store: FirestoreService,
    endpoint_id: str,
    *,
    endpoint_platform: Optional[str] = None,
) -> Dict[str, Any]:
    """Runs the full pipeline for a single endpoint doc id.

    - Updates scan_status in Firestore (scanning/completed/failed)
    - Saves summary + application_summaries back to Firestore

    Returns a small summary dict (used for logs).
    """

    # Ensure the NVD dataset is present before invoking the product pipeline.
    # (Startup bootstrapping is non-blocking in production.)
    ensure_nvd_dataset_present(blocking=True)

    if not ORCHESTRATOR.exists():
        raise FileNotFoundError(f"Orchestrator not found: {ORCHESTRATOR}")

    # 1) Fetch endpoint doc from the agent collection (backend responsibility)
    doc = endpoints_store.get_endpoint(endpoint_id)
    applications = doc.get("applications") or []
    if not isinstance(applications, list):
        raise ValueError("Endpoint 'applications' field must be an array")

    payload = {
        "endpoint_id": endpoint_id,
        "applications": applications,
    }

    # 2) Run orchestrator using --endpoint-json (no Firestore access inside product scripts)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as tmp:
        json.dump(payload, tmp, ensure_ascii=False, indent=2)
        tmp_path = tmp.name

    cmd = [
        sys.executable,
        str(ORCHESTRATOR),
        "--endpoint-json",
        str(tmp_path),
        "--doc-id",
        endpoint_id,
    ]
    if endpoint_platform:
        cmd += ["--endpoint-platform", endpoint_platform]

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        with _proc_lock:
            _running_procs[endpoint_id] = proc

        stdout, stderr = proc.communicate()
    finally:
        with _proc_lock:
            _running_procs.pop(endpoint_id, None)
        try:
            Path(tmp_path).unlink(missing_ok=True)
        except Exception:
            pass

    if proc.returncode != 0:
        # If killed via cancel, returncode is negative on Unix or 1 on Windows.
        was_cancelled = proc.returncode < 0 or (proc.returncode == 1 and not stderr)
        if was_cancelled:
            scans_store.update_scan_status(
                endpoint_id,
                status="failed",
                error_message="Scan was cancelled by user",
            )
            raise RuntimeError(f"Scan cancelled for {endpoint_id}")

        scans_store.update_scan_status(
            endpoint_id,
            status="failed",
            error_message=(stderr[-8000:] if stderr else stdout[-8000:]),
        )
        raise RuntimeError(f"Scan failed for {endpoint_id} (exit={proc.returncode})")

    bundle_rel = _extract_bundle_path(stdout)
    if not bundle_rel:
        scans_store.update_scan_status(
            endpoint_id,
            status="failed",
            error_message="Scan finished but bundle path was not found in orchestrator output",
        )
        raise RuntimeError("Bundle path not found in orchestrator stdout")

    bundle_path = (ROOT / Path(bundle_rel)).resolve()
    if not bundle_path.exists():
        scans_store.update_scan_status(
            endpoint_id,
            status="failed",
            error_message=f"Bundle JSON not found at: {bundle_path}",
        )
        raise RuntimeError("Bundle JSON missing")

    with bundle_path.open("r", encoding="utf-8") as f:
        bundle = json.load(f)

    artifacts = dict(bundle.get("artifacts") or {})

    # Persist detailed artifacts to durable storage (Container Apps filesystem is ephemeral).
    blob_cfg = _get_artifacts_blob_config()
    scan_dir_name = _extract_scan_dir_name(bundle) or "latest"
    if blob_cfg and artifacts.get("scored"):
        scored_rel = str(artifacts.get("scored"))
        scored_path = (ROOT / Path(scored_rel)).resolve()
        if scored_path.is_file():
            blob_name = f"{blob_cfg['prefix']}/{endpoint_id}/{scan_dir_name}/product_cve_scored.json"
            try:
                upload_blob_from_path(
                    account_name=blob_cfg["account"],
                    container_name=blob_cfg["container"],
                    blob_name=blob_name,
                    file_path=scored_path,
                    content_type="application/json",
                )
                artifacts["scored_blob"] = {
                    "account": blob_cfg["account"],
                    "container": blob_cfg["container"],
                    "blob": blob_name,
                }
            except Exception as e:
                # Do not fail the scan; the summary still persists to Firestore.
                artifacts["scored_blob_error"] = f"{type(e).__name__}: {e}"

    endpoint_summary = bundle.get("endpoint_summary") or {}
    application_summaries = bundle.get("application_summaries") or []

    try:
        scans_store.save_scan_results(
            endpoint_id,
            endpoint_summary=endpoint_summary,
            application_summaries=application_summaries,
            bundle_artifacts=artifacts,
        )
    except Exception as e:
        # If we can't persist results, the UI will appear to "lose" scans.
        # Best-effort: record the failure in the scan-results doc.
        try:
            scans_store.update_scan_status(
                endpoint_id,
                status="failed",
                error_message=(
                    "Scan completed but failed to persist results to Firestore scan-results collection. "
                    f"Error: {type(e).__name__}: {e}"
                ),
            )
        except Exception:
            pass
        raise

    return {
        "endpoint_id": endpoint_id,
        "endpoint_risk_score_0_100": endpoint_summary.get("endpoint_risk_score_0_100"),
        "endpoint_risk_tier": endpoint_summary.get("endpoint_risk_tier"),
        "bundle_path": str(bundle_path),
    }
