from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException, Query


ROOT = Path(__file__).resolve().parent
ORCHESTRATOR = ROOT / "product" / "run_endpoint_scan.py"


app = FastAPI(title="Endpoint Risk Scanner API")


@app.post("/scan/{doc_id}")
def scan_firestore_doc(
    doc_id: str,
    endpoint_platform: Optional[Literal["windows", "macos", "linux", "unknown"]] = Query(
        default=None,
        description="Optional override for platform filtering during CVE mapping",
    ),
):
    """Run an on-demand scan for a Firestore endpoint doc and return the bundle JSON."""

    if not ORCHESTRATOR.exists():
        raise HTTPException(status_code=500, detail=f"Orchestrator not found: {ORCHESTRATOR}")

    service_account = os.getenv("FIRESTORE_SERVICE_ACCOUNT")
    if not service_account:
        raise HTTPException(
            status_code=500,
            detail=(
                "Missing env var FIRESTORE_SERVICE_ACCOUNT (path to service account key JSON). "
                "Example: product/secrets/serviceAccountKey.json"
            ),
        )

    firestore_collection = os.getenv("FIRESTORE_COLLECTION", "endpoint data")
    firestore_project_id = os.getenv("FIRESTORE_PROJECT_ID")

    cmd = [
        sys.executable,
        str(ORCHESTRATOR),
        "--firestore-service-account",
        service_account,
        "--firestore-collection",
        firestore_collection,
        "--firestore-doc-id",
        doc_id,
    ]
    if firestore_project_id:
        cmd += ["--firestore-project-id", firestore_project_id]
    if endpoint_platform:
        cmd += ["--endpoint-platform", endpoint_platform]

    proc = subprocess.run(
        cmd,
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )

    if proc.returncode != 0:
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Scan failed",
                "exit_code": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
            },
        )

    match = re.search(r"^Bundle:\s*(.+)\s*$", proc.stdout, flags=re.MULTILINE)
    if not match:
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Scan finished but bundle path was not found in orchestrator output",
                "stdout": proc.stdout,
                "stderr": proc.stderr,
            },
        )

    bundle_rel = match.group(1).strip()
    bundle_path = (ROOT / Path(bundle_rel)).resolve()
    if not bundle_path.exists():
        raise HTTPException(
            status_code=500,
            detail=f"Bundle JSON not found at: {bundle_path}",
        )

    with bundle_path.open("r", encoding="utf-8") as f:
        return json.load(f)
