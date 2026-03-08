from __future__ import annotations

import gzip
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Optional


_ROOT = Path(__file__).resolve().parents[1]


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

    # Validate JSON early to fail fast on bad secrets.
    json.loads(raw)

    secrets_dir = Path(tempfile.gettempdir()) / "endpoint-risk-secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)
    key_path = secrets_dir / "serviceAccountKey.json"
    key_path.write_text(raw, encoding="utf-8")

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


def _ensure_nvd_dataset_present() -> Optional[str]:
    """Ensure product/nvd_cves_all.json exists (download if configured)."""

    target_path = Path(
        os.getenv("NVD_DATASET_PATH") or (_ROOT / "product" / "nvd_cves_all.json")
    )
    if target_path.exists():
        return str(target_path)

    url = os.getenv("NVD_DATASET_URL")
    if not url:
        return None

    _download_to_path(url, target_path)
    return str(target_path)


def bootstrap_runtime() -> None:
    """Best-effort runtime bootstrap.

    Safe to call multiple times.
    """

    _write_service_account_from_env()
    _ensure_nvd_dataset_present()
