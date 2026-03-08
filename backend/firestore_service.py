from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from google.cloud import firestore
from google.oauth2 import service_account


_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_SA_KEY = _ROOT / "product" / "secrets" / "serviceAccountKey.json"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _build_client(project_id: Optional[str]) -> firestore.Client:
    """Build a Firestore client using the best available credentials.

    Priority:
    1. GOOGLE_APPLICATION_CREDENTIALS env var (standard GCP approach)
    2. product/secrets/serviceAccountKey.json (local dev convenience)
    3. ADC (Cloud Run / gcloud auth application-default login)
    """
    sa_path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS") or (
        str(_DEFAULT_SA_KEY) if _DEFAULT_SA_KEY.exists() else None
    )

    if sa_path and Path(sa_path).exists():
        creds = service_account.Credentials.from_service_account_file(str(sa_path))
        return firestore.Client(project=project_id, credentials=creds)

    return firestore.Client(project=project_id)


class FirestoreService:
    def __init__(
        self,
        *,
        collection_name: str,
        project_id: Optional[str] = None,
        allow_writes: bool = True,
    ) -> None:
        self._client = _build_client(project_id)
        self._collection = self._client.collection(collection_name)
        self._collection_name = collection_name
        self._allow_writes = allow_writes

    @property
    def collection_name(self) -> str:
        return self._collection_name

    def list_endpoints(self, limit: int = 200) -> List[Dict[str, Any]]:
        docs = self._collection.limit(limit).stream()
        items: List[Dict[str, Any]] = []
        for doc in docs:
            data = doc.to_dict() or {}
            items.append({"endpoint_id": doc.id, **data})
        return items

    def get_endpoint(self, endpoint_id: str) -> Dict[str, Any]:
        ref = self._collection.document(endpoint_id)
        snap = ref.get()
        if not snap.exists:
            raise KeyError(f"Endpoint not found: {endpoint_id}")
        data = snap.to_dict() or {}
        return {"endpoint_id": snap.id, **data}

    def update_scan_status(
        self,
        endpoint_id: str,
        *,
        status: str,
        error_message: Optional[str] = None,
        extra_fields: Optional[Dict[str, Any]] = None,
    ) -> None:
        if not self._allow_writes:
            raise RuntimeError(
                "Writes are disabled for this FirestoreService instance "
                f"(collection={self._collection_name})."
            )
        ref = self._collection.document(endpoint_id)

        update: Dict[str, Any] = {
            "scan_status": status,
            "scan_error_message": error_message,
        }
        if status == "scanning":
            update["scan_started_at"] = _utc_now()
        if status in ("completed", "failed"):
            update["last_scanned_at"] = _utc_now()

        if extra_fields:
            update.update(extra_fields)

        ref.set(update, merge=True)

    def save_scan_results(
        self,
        endpoint_id: str,
        *,
        endpoint_summary: Dict[str, Any],
        application_summaries: List[Dict[str, Any]],
        bundle_artifacts: Optional[Dict[str, Any]] = None,
    ) -> None:
        if not self._allow_writes:
            raise RuntimeError(
                "Writes are disabled for this FirestoreService instance "
                f"(collection={self._collection_name})."
            )
        ref = self._collection.document(endpoint_id)

        # Keep practical UI fields at top-level.
        es = endpoint_summary or {}
        update: Dict[str, Any] = {
            "scan_status": "completed",
            "scan_error_message": None,
            "last_scanned_at": _utc_now(),
            "endpoint_risk_score": es.get("endpoint_risk_score"),
            "endpoint_risk_score_0_100": es.get("endpoint_risk_score_0_100"),
            "endpoint_risk_tier": es.get("endpoint_risk_tier"),
            "application_count_with_cves": es.get("application_count_with_cves"),
            "total_cve_count": es.get("total_cve_count"),
            "total_kev_count": es.get("total_kev_count"),
            "total_exploit_evidence_count": es.get("total_exploit_evidence_count"),
            "application_summaries": application_summaries,
            "latest_endpoint_summary": es,
        }
        if bundle_artifacts:
            update["latest_scan_artifacts"] = bundle_artifacts

        ref.set(update, merge=True)

    def merge_fields(self, endpoint_id: str, fields: Dict[str, Any]) -> None:
        if not self._allow_writes:
            raise RuntimeError(
                "Writes are disabled for this FirestoreService instance "
                f"(collection={self._collection_name})."
            )
        ref = self._collection.document(endpoint_id)
        ref.set(dict(fields or {}), merge=True)


def firestore_from_env() -> FirestoreService:
    """Backward-compatible factory.

    Historically the backend used a single env var (FIRESTORE_COLLECTION) which
    defaulted to the agent collection ("endpoint data"). We keep this behavior
    for reads.
    """

    collection_name = os.getenv("FIRESTORE_ENDPOINT_COLLECTION") or os.getenv(
        "FIRESTORE_COLLECTION", "endpoint data"
    )
    project_id = os.getenv("FIRESTORE_PROJECT_ID") or None
    return FirestoreService(
        collection_name=collection_name,
        project_id=project_id,
        allow_writes=False,
    )


def firestore_endpoints_from_env() -> FirestoreService:
    """Firestore client for agent-reported endpoint documents (read-only)."""

    collection_name = os.getenv("FIRESTORE_ENDPOINT_COLLECTION") or os.getenv(
        "FIRESTORE_COLLECTION", "endpoint data"
    )
    project_id = os.getenv("FIRESTORE_PROJECT_ID") or None
    return FirestoreService(
        collection_name=collection_name,
        project_id=project_id,
        allow_writes=False,
    )


def firestore_scans_from_env() -> FirestoreService:
    """Firestore client for system-generated scan status/results.

    This MUST NOT be the same collection as the agent endpoint collection.
    """

    endpoint_collection = os.getenv("FIRESTORE_ENDPOINT_COLLECTION") or os.getenv(
        "FIRESTORE_COLLECTION", "endpoint data"
    )

    # Use a default that is easy to spot in the Firestore console.
    # (Avoid spaces to prevent confusion in tooling and dashboards.)
    collection_name = os.getenv("FIRESTORE_SCAN_COLLECTION") or "endpoint_scans"

    # Safety: never allow scan writes into the agent endpoint collection.
    if collection_name.strip() == endpoint_collection.strip():
        collection_name = "endpoint_scans"
        if collection_name.strip() == endpoint_collection.strip():
            collection_name = "endpoint_scans_v2"
    project_id = os.getenv("FIRESTORE_PROJECT_ID") or None
    return FirestoreService(
        collection_name=collection_name,
        project_id=project_id,
        allow_writes=True,
    )
