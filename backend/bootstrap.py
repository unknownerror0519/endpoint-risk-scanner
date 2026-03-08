from __future__ import annotations

import base64
import gzip
import json
import os
import shutil
import tempfile
import threading
from pathlib import Path
from typing import Optional


_ROOT = Path(__file__).resolve().parents[1]


_nvd_download_lock = threading.Lock()
_nvd_download_started = False


def _parse_service_account_payload(raw: str) -> dict:
    """Parse a service-account JSON payload from an environment variable.

    Container platforms sometimes inject secrets in non-strict JSON forms
    (e.g., Python dict-literal strings using single quotes). We accept both.
    """

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        # Some platforms/CLIs can mangle quotes in JSON when storing secrets.
        # A robust alternative is to store base64-encoded JSON.
        try:
            decoded = base64.b64decode(raw, validate=True).decode("utf-8")
        except Exception as e:
            raise ValueError(
                "Invalid FIRESTORE_SERVICE_ACCOUNT_JSON secret. "
                "Provide strict JSON or base64-encoded JSON."
            ) from e
        parsed = json.loads(decoded)
    if not isinstance(parsed, dict):
        raise ValueError("Service account payload must be a JSON object")
    return parsed


def _write_service_account_from_env() -> Optional[str]:
    """Materialize a Firestore service-account key from an env var.

    For platforms like Hugging Face Spaces, it's common to store the service
    account JSON as a secret environment variable.
    """

    # If a credential path is already configured, do nothing.
    if os.getenv("GOOGLE_APPLICATION_CREDENTIALS"):
        return None

    raw = os.getenv("FIRESTORE_SERVICE_ACCOUNT_JSON")
    if not raw:
        return None

    # Validate and normalize early to fail fast on bad secrets.
    normalized = json.dumps(_parse_service_account_payload(raw), ensure_ascii=False)

    secrets_dir = Path(tempfile.gettempdir()) / "endpoint-risk-secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)
    key_path = secrets_dir / "serviceAccountKey.json"
    key_path.write_text(normalized, encoding="utf-8")

    # Ensure other code reading FIRESTORE_SERVICE_ACCOUNT_JSON sees strict JSON.
    os.environ["FIRESTORE_SERVICE_ACCOUNT_JSON"] = normalized

    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(key_path)
    return str(key_path)


def _download_to_path(url: str, target_path: Path) -> None:
    try:
        import requests  # type: ignore
    except Exception as e:  # pragma: no cover
        raise RuntimeError("Missing dependency 'requests'.") from e

    target_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = target_path.with_suffix(target_path.suffix + ".tmp")

    with requests.get(url, stream=True, timeout=1800) as resp:
        resp.raise_for_status()

        # Ensure urllib3 doesn't try to auto-decode gzip when we want the raw stream.
        if hasattr(resp.raw, "decode_content"):
            resp.raw.decode_content = False

        if url.lower().endswith(".gz"):
            with gzip.GzipFile(fileobj=resp.raw) as gz, tmp_path.open("wb") as f:
                shutil.copyfileobj(gz, f, length=1024 * 1024)
        else:
            with tmp_path.open("wb") as f:
                for chunk in resp.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        f.write(chunk)

    tmp_path.replace(target_path)


def _download_from_azure_blob(
    *,
    account_name: str,
    container_name: str,
    blob_name: str,
    target_path: Path,
) -> None:
    """Download a blob to target_path using Azure identity (no SAS URL)."""

    try:
        from azure.identity import DefaultAzureCredential  # type: ignore
        from azure.storage.blob import BlobClient  # type: ignore
    except Exception as e:  # pragma: no cover
        raise RuntimeError(
            "Missing Azure dependencies. Install 'azure-identity' and 'azure-storage-blob'."
        ) from e

    target_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = target_path.with_suffix(target_path.suffix + ".tmp")

    account_url = f"https://{account_name}.blob.core.windows.net"
    credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
    blob = BlobClient(
        account_url=account_url,
        container_name=container_name,
        blob_name=blob_name,
        credential=credential,
    )

    stream = blob.download_blob(max_concurrency=1)
    with tmp_path.open("wb") as f:
        stream.readinto(f)

    tmp_path.replace(target_path)


def _ensure_nvd_dataset_present() -> Optional[str]:
    """Ensure product/nvd_cves_all.json exists (download if configured)."""

    target_path = Path(
        os.getenv("NVD_DATASET_PATH") or (_ROOT / "product" / "nvd_cves_all.json")
    )
    if target_path.exists():
        return str(target_path)

    # Prefer Azure Blob auth via managed identity (no SAS needed).
    account_name = os.getenv("NVD_AZURE_STORAGE_ACCOUNT")
    container_name = os.getenv("NVD_AZURE_CONTAINER") or "datasets"
    blob_name = os.getenv("NVD_AZURE_BLOB") or "nvd_cves_all.json"

    if account_name:
        _download_from_azure_blob(
            account_name=account_name,
            container_name=container_name,
            blob_name=blob_name,
            target_path=target_path,
        )
        return str(target_path)

    # Fallback: HTTP(S) URL (optionally SAS)
    url = os.getenv("NVD_DATASET_URL")
    if not url:
        return None

    _download_to_path(url, target_path)
    return str(target_path)


def ensure_nvd_dataset_present(*, blocking: bool) -> Optional[str]:
    """Ensure the NVD dataset exists.

    - If blocking=True, downloads inline (callers should expect this may take time).
    - If blocking=False, starts a single background download thread if needed.
    """

    if blocking:
        return _ensure_nvd_dataset_present()

    # Non-blocking: if already present or not configured, do nothing.
    target_path = Path(
        os.getenv("NVD_DATASET_PATH") or (_ROOT / "product" / "nvd_cves_all.json")
    )

    has_http_url = bool(os.getenv("NVD_DATASET_URL"))
    has_azure_blob = bool(os.getenv("NVD_AZURE_STORAGE_ACCOUNT"))

    if target_path.exists() or not (has_http_url or has_azure_blob):
        return str(target_path) if target_path.exists() else None

    global _nvd_download_started
    with _nvd_download_lock:
        if _nvd_download_started:
            return None
        _nvd_download_started = True

    print(f"Starting background NVD dataset download to {target_path}...")

    def _bg() -> None:
        try:
            _ensure_nvd_dataset_present()
        except Exception as e:
            # Do not crash the process; scans will handle missing dataset explicitly.
            print(f"NVD dataset background download failed: {type(e).__name__}: {e}")

    threading.Thread(target=_bg, name="nvd-dataset-download", daemon=True).start()
    return None


def bootstrap_runtime() -> None:
    """Best-effort runtime bootstrap.

    Safe to call multiple times.
    """

    _write_service_account_from_env()

    mode = (os.getenv("NVD_DATASET_DOWNLOAD_MODE") or "background").strip().lower()
    blocking = mode in ("blocking", "sync", "inline")
    ensure_nvd_dataset_present(blocking=blocking)
