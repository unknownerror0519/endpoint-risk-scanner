from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional


def _get_blob_client(*, account_name: str, container_name: str, blob_name: str):
    try:
        from azure.identity import DefaultAzureCredential  # type: ignore
        from azure.storage.blob import BlobClient  # type: ignore
    except Exception as e:  # pragma: no cover
        raise RuntimeError(
            "Missing Azure dependencies. Install 'azure-identity' and 'azure-storage-blob'."
        ) from e

    account_url = f"https://{account_name}.blob.core.windows.net"
    credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
    return BlobClient(
        account_url=account_url,
        container_name=container_name,
        blob_name=blob_name,
        credential=credential,
    )


def download_blob_text(*, account_name: str, container_name: str, blob_name: str) -> str:
    blob = _get_blob_client(
        account_name=account_name,
        container_name=container_name,
        blob_name=blob_name,
    )
    stream = blob.download_blob(max_concurrency=1)
    data = stream.readall()
    if isinstance(data, bytes):
        return data.decode("utf-8")
    return str(data)


def download_blob_json(*, account_name: str, container_name: str, blob_name: str) -> Any:
    return json.loads(
        download_blob_text(
            account_name=account_name,
            container_name=container_name,
            blob_name=blob_name,
        )
    )


def upload_blob_from_path(
    *,
    account_name: str,
    container_name: str,
    blob_name: str,
    file_path: Path,
    content_type: Optional[str] = None,
) -> None:
    if not file_path.is_file():
        raise FileNotFoundError(str(file_path))

    blob = _get_blob_client(
        account_name=account_name,
        container_name=container_name,
        blob_name=blob_name,
    )

    kwargs = {}
    if content_type:
        try:
            from azure.storage.blob import ContentSettings  # type: ignore

            kwargs["content_settings"] = ContentSettings(content_type=content_type)
        except Exception:
            pass

    with file_path.open("rb") as f:
        blob.upload_blob(f, overwrite=True, **kwargs)
