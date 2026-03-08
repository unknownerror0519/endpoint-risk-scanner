"""Update the local NVD CVE dataset (JSON 2.0) safely.

Why this exists
- The matcher relies on `product/nvd_cves_all.json`.
- If that dataset is old, you will miss newer CVEs and newer affected-version ranges.

Safety
- Creates a timestamped backup next to the output file.
- Writes to a temporary file and then replaces atomically.
- Does not modify any other pipeline files.

Input/Output format
This script expects the *NVD JSON 2.0* shape used by this repo:
{
  "total_downloaded": <int>,
  "total_available": <int>,
  "downloaded_at": <iso str>,
  "vulnerabilities": [ {"cve": {...}}, ... ]
}

It fetches new/updated CVEs using the NVD 2.0 REST API:
https://services.nvd.nist.gov/rest/json/cves/2.0

Usage (no API key; slower / stricter rate limits):
  C:/Users/YASINDU/AppData/Local/Programs/Python/Python314/python.exe product/update_nvd_dataset.py

Usage (recommended with API key):
  setx NVD_API_KEY "<your_key>"
  C:/Users/YASINDU/AppData/Local/Programs/Python/Python314/python.exe product/update_nvd_dataset.py

Notes
- NVD requires RFC3339 timestamps with milliseconds, e.g. 2024-05-15T17:15:14.250Z
- This script uses lastModified windowing to capture updates.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _to_rfc3339_millis_z(t: dt.datetime) -> str:
    t = t.astimezone(dt.timezone.utc)
    # Keep milliseconds.
    return t.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _parse_rfc3339(s: str) -> Optional[dt.datetime]:
    if not s or not isinstance(s, str):
        return None
    # Accept both ...Z and ...+00:00.
    try:
        if s.endswith("Z"):
            s2 = s[:-1] + "+00:00"
        else:
            s2 = s
        return dt.datetime.fromisoformat(s2)
    except ValueError:
        return None


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _write_json_atomic(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", dir=str(path.parent), suffix=".tmp") as tf:
        json.dump(data, tf, ensure_ascii=False)
        tf.write("\n")
        tmp_name = tf.name
    os.replace(tmp_name, str(path))


def _backup_file(path: Path) -> Path:
    stamp = _utc_now().strftime("%Y%m%d_%H%M%SZ")
    backup = path.with_suffix(path.suffix + f".bak_{stamp}")
    shutil.copy2(path, backup)
    return backup


def _iter_vulnerabilities(dataset: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    vulns = dataset.get("vulnerabilities")
    if isinstance(vulns, list):
        for v in vulns:
            if isinstance(v, dict) and isinstance(v.get("cve"), dict):
                yield v


def _max_last_modified(dataset: Dict[str, Any]) -> Optional[dt.datetime]:
    max_t: Optional[dt.datetime] = None
    for v in _iter_vulnerabilities(dataset):
        cve = v.get("cve") or {}
        lm = cve.get("lastModified")
        t = _parse_rfc3339(lm) if isinstance(lm, str) else None
        if t is None:
            continue
        if max_t is None or t > max_t:
            max_t = t
    return max_t


def _http_get_json(url: str, api_key: Optional[str]) -> Dict[str, Any]:
    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key

    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=60) as resp:
        body = resp.read().decode("utf-8", errors="replace")
        return json.loads(body)


def _build_url(last_mod_start: str, last_mod_end: str, start_index: int, results_per_page: int) -> str:
    query = {
        "lastModStartDate": last_mod_start,
        "lastModEndDate": last_mod_end,
        "startIndex": str(int(start_index)),
        "resultsPerPage": str(int(results_per_page)),
    }
    return API_BASE + "?" + urllib.parse.urlencode(query)


def _fetch_window(
    *,
    api_key: Optional[str],
    last_mod_start: str,
    last_mod_end: str,
    results_per_page: int,
    polite_sleep_s: float,
) -> Tuple[List[Dict[str, Any]], int]:
    """Fetch all vulnerabilities for a lastModified window."""

    out: List[Dict[str, Any]] = []
    start_index = 0
    total = None

    while True:
        url = _build_url(last_mod_start, last_mod_end, start_index, results_per_page)
        payload = _http_get_json(url, api_key)

        total_results = payload.get("totalResults")
        if isinstance(total_results, int):
            total = total_results

        vulns = payload.get("vulnerabilities")
        batch = [v for v in vulns if isinstance(v, dict) and isinstance(v.get("cve"), dict)] if isinstance(vulns, list) else []
        out.extend(batch)

        if not batch:
            break

        start_index += len(batch)
        if total is not None and start_index >= total:
            break

        # Be polite with rate limits.
        if polite_sleep_s > 0:
            time.sleep(polite_sleep_s)

    return out, int(total or len(out))


def _merge(
    existing: Dict[str, Any],
    fetched: List[Dict[str, Any]],
) -> Tuple[Dict[str, Any], int, int]:
    """Merge fetched vulnerabilities into existing dataset by CVE id.

    Returns: (new_dataset, added_count, updated_count)
    """

    existing_vulns = list(_iter_vulnerabilities(existing))

    by_id: Dict[str, Dict[str, Any]] = {}
    for v in existing_vulns:
        cve = v.get("cve") or {}
        cid = cve.get("id")
        if isinstance(cid, str) and cid.startswith("CVE-"):
            by_id[cid] = v

    added = 0
    updated = 0
    for v in fetched:
        cve = v.get("cve") or {}
        cid = cve.get("id")
        if not isinstance(cid, str) or not cid.startswith("CVE-"):
            continue
        if cid in by_id:
            by_id[cid] = v
            updated += 1
        else:
            by_id[cid] = v
            added += 1

    merged_list = list(by_id.values())
    merged_list.sort(key=lambda x: str((x.get("cve") or {}).get("id") or ""))

    new_ds = dict(existing)
    new_ds["vulnerabilities"] = merged_list
    new_ds["total_downloaded"] = int(len(merged_list))
    new_ds["downloaded_at"] = _to_rfc3339_millis_z(_utc_now())

    return new_ds, added, updated


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Update local NVD JSON 2.0 dataset safely")
    parser.add_argument(
        "--in",
        dest="in_path",
        default=str(Path(__file__).resolve().parent / "nvd_cves_all.json"),
        help="Input dataset path (default: product/nvd_cves_all.json)",
    )
    parser.add_argument(
        "--out",
        dest="out_path",
        default=None,
        help="Output dataset path (default: overwrite --in)",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="NVD API key (default: env NVD_API_KEY)",
    )
    parser.add_argument(
        "--results-per-page",
        type=int,
        default=2000,
        help="Page size (max 2000 for NVD 2.0)",
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=0.65,
        help="Seconds to sleep between pages (rate-limit friendliness)",
    )
    parser.add_argument(
        "--last-mod-start",
        default=None,
        help="Override lastModified start date (RFC3339, e.g. 2024-05-15T00:00:00.000Z)",
    )
    parser.add_argument(
        "--last-mod-end",
        default=None,
        help="Override lastModified end date (RFC3339)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch and report counts but do not write output",
    )

    args = parser.parse_args(argv)

    in_path = Path(args.in_path)
    out_path = Path(args.out_path) if args.out_path else in_path

    if not in_path.exists():
        print(f"Input dataset not found: {in_path}", file=sys.stderr)
        return 2

    api_key = args.api_key or os.environ.get("NVD_API_KEY")

    existing = _read_json(in_path)
    if not isinstance(existing, dict) or not isinstance(existing.get("vulnerabilities"), list):
        print("Input file is not the expected NVD JSON 2.0 dataset shape.", file=sys.stderr)
        return 2

    max_lm = _max_last_modified(existing)
    if max_lm is None:
        print("Could not determine max lastModified from existing dataset.", file=sys.stderr)
        return 2

    # Start just after the known max lastModified to avoid refetching everything.
    start_dt = max_lm + dt.timedelta(milliseconds=1)
    end_dt = _utc_now()

    last_mod_start = args.last_mod_start or _to_rfc3339_millis_z(start_dt)
    last_mod_end = args.last_mod_end or _to_rfc3339_millis_z(end_dt)

    print(f"Input:  {in_path}")
    print(f"Output: {out_path}")
    print(f"Existing vulnerabilities: {len(existing.get('vulnerabilities') or [])}")
    print(f"Max lastModified in dataset: {max_lm.isoformat()}")
    print(f"Fetching window: {last_mod_start}  ->  {last_mod_end}")

    fetched, total_available = _fetch_window(
        api_key=api_key,
        last_mod_start=last_mod_start,
        last_mod_end=last_mod_end,
        results_per_page=max(1, min(2000, int(args.results_per_page))),
        polite_sleep_s=max(0.0, float(args.sleep)),
    )

    print(f"Fetched vulnerabilities: {len(fetched)} (totalResults={total_available})")

    if args.dry_run:
        print("Dry-run: not writing output.")
        return 0

    # Backup only if overwriting an existing file.
    if out_path.exists():
        backup = _backup_file(out_path)
        print(f"Backup written: {backup}")

    merged, added, updated = _merge(existing, fetched)
    merged["total_available"] = int(max(int(merged.get("total_downloaded") or 0), int(existing.get("total_available") or 0), int(total_available)))

    _write_json_atomic(out_path, merged)
    print(f"Wrote updated dataset: {out_path}")
    print(f"Added: {added}, Updated: {updated}, Total now: {merged.get('total_downloaded')}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
