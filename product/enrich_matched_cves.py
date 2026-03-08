"""CVE enrichment layer (one endpoint at a time).

Reads matched CVEs per installed product and enriches each CVE with dynamic
threat signals:
- CISA KEV status (required)
- EPSS score + percentile (required)
- Vulners exploit evidence (optional: local JSON or API key)
- ExploitDB exploit evidence (optional: local JSON or CSV)

Hard rules:
- Deterministic mapping by cve_id only (no fuzzy matching)
- Do not modify input files
- Do not score risk or call ML models
- Missing Vulners/ExploitDB must not crash

Outputs:
- product/output/product_cve_enriched.json

Expected input:
- product/output/product_cve_matches.json

Run:
  python product/enrich_matched_cves.py
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


ROOT = Path(__file__).resolve().parents[1]


class RequiredInputMissingError(RuntimeError):
    pass


@dataclass
class VulnersApiStats:
    """Runtime stats for optional Vulners API mode.

    This is purely informational (printed); it does not change output schema.
    """

    calls_attempted: int = 0
    http_200: int = 0
    http_403: int = 0
    http_429: int = 0
    http_other: int = 0
    exceptions: int = 0


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _find_first_existing(candidates: Sequence[Path]) -> Optional[Path]:
    for p in candidates:
        if p.exists():
            return p
    return None


def _resolve_candidates(rel_paths: Sequence[str]) -> List[Path]:
    return [ROOT / p for p in rel_paths]


def _coerce_float(value: Any) -> float:
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    s = str(value).strip()
    if not s:
        return 0.0
    try:
        return float(s)
    except ValueError:
        return 0.0


def _normalize_header(name: str) -> str:
    return name.strip().lower().replace(" ", "_")


def _collect_unique_cve_ids(matches: List[Dict[str, Any]]) -> List[str]:
    seen: Set[str] = set()
    ordered: List[str] = []
    for product in matches:
        for cve in product.get("matched_cves", []) or []:
            cve_id = (cve.get("cve_id") or "").strip()
            if not cve_id:
                continue
            if cve_id not in seen:
                seen.add(cve_id)
                ordered.append(cve_id)
    return ordered


# -------------------------
# KEV (required)
# -------------------------


def find_kev_path() -> Path:
    candidates = _resolve_candidates(
        [
            "kev/kev_catalog.json",
            "known_exploited_vulnerabilities.json",
            "data/known_exploited_vulnerabilities.json",
        ]
    )
    path = _find_first_existing(candidates)
    if not path:
        raise RequiredInputMissingError(
            "KEV file not found. Expected one of: "
            + ", ".join(str(p.relative_to(ROOT)) for p in candidates)
        )
    return path


def load_kev_map(kev_path: Path) -> Dict[str, Dict[str, Any]]:
    """Return kev_map[cve_id] = {kev_flag: True, kev_date_added: <str|None>}"""

    data = _read_json(kev_path)

    vulns = []
    if isinstance(data, dict):
        # Common KEV format: { "vulnerabilities": [ {"cveID":..., "dateAdded":...}, ... ] }
        vulns = data.get("vulnerabilities") or data.get("Vulnerabilities") or []
    elif isinstance(data, list):
        vulns = data

    kev_map: Dict[str, Dict[str, Any]] = {}
    for v in vulns if isinstance(vulns, list) else []:
        if not isinstance(v, dict):
            continue
        cve_id = (v.get("cveID") or v.get("cve") or v.get("cve_id") or "").strip()
        if not cve_id:
            continue
        date_added = v.get("dateAdded") or v.get("date_added")
        kev_map[cve_id] = {
            "kev_flag": True,
            "kev_date_added": str(date_added) if date_added else None,
        }

    return kev_map


# -------------------------
# EPSS (required)
# -------------------------


def _choose_epss_file(path: Path) -> Path:
    if path.is_file():
        return path
    if path.is_dir():
        csv_files = sorted([p for p in path.rglob("*.csv") if p.is_file()])
        if not csv_files:
            raise RequiredInputMissingError(
                f"EPSS path exists but contains no .csv files: {path}"
            )
        return csv_files[0]
    raise RequiredInputMissingError(f"EPSS path is not a file or directory: {path}")


def find_epss_path() -> Path:
    candidates = _resolve_candidates(
        [
            "epss_scores",
            "epss_scores.csv",
            "data/epss_scores",
            "data/epss_scores.csv",
        ]
    )
    path = _find_first_existing(candidates)
    if not path:
        raise RequiredInputMissingError(
            "EPSS file not found. Expected one of: "
            + ", ".join(str(p.relative_to(ROOT)) for p in candidates)
        )
    return _choose_epss_file(path)


@dataclass(frozen=True)
class EPSSRecord:
    epss: float
    epss_percentile: float


def load_epss_map(epss_csv_path: Path) -> Dict[str, EPSSRecord]:
    """Load EPSS CSV into epss_map[cve_id] = EPSSRecord."""

    epss_map: Dict[str, EPSSRecord] = {}

    with epss_csv_path.open("r", encoding="utf-8", newline="") as f:
        # Skip comment lines (some feeds include them)
        pos = f.tell()
        first = f.readline()
        while first.startswith("#"):
            pos = f.tell()
            first = f.readline()
        f.seek(pos)

        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise RequiredInputMissingError(f"EPSS CSV has no header: {epss_csv_path}")

        # Normalize headers
        header_map = {_normalize_header(h): h for h in reader.fieldnames}

        def col(*names: str) -> Optional[str]:
            for n in names:
                key = _normalize_header(n)
                if key in header_map:
                    return header_map[key]
            return None

        cve_col = col("cve_id", "cve", "cveid")
        epss_col = col("epss", "epss_score", "score")
        pct_col = col("epss_percentile", "percentile")

        if not cve_col or not epss_col or not pct_col:
            raise RequiredInputMissingError(
                "EPSS CSV missing required columns. "
                f"Found headers: {reader.fieldnames}. "
                "Need cve/cve_id, epss, percentile."
            )

        for row in reader:
            if not row:
                continue
            cve_id = (row.get(cve_col) or "").strip()
            if not cve_id:
                continue
            epss = _coerce_float(row.get(epss_col))
            percentile = _coerce_float(row.get(pct_col))
            epss_map[cve_id] = EPSSRecord(epss=epss, epss_percentile=percentile)

    return epss_map


# -------------------------
# Vulners (optional)
# -------------------------


def find_vulners_local_path() -> Optional[Path]:
    candidates = _resolve_candidates(
        [
            "vulners_data.json",
            "data/vulners_data.json",
            "product/data/vulners_data.json",
        ]
    )
    return _find_first_existing(candidates)


@dataclass
class ExploitEvidence:
    flag: bool
    reference_count: int
    ids: List[str]


def _empty_evidence() -> ExploitEvidence:
    return ExploitEvidence(flag=False, reference_count=0, ids=[])


def load_vulners_map_from_local(vulners_path: Path) -> Dict[str, ExploitEvidence]:
    """Best-effort local Vulners export parser.

    Expected shapes vary; we keep this deterministic and strict by CVE ID.
    """

    data = _read_json(vulners_path)
    out: Dict[str, ExploitEvidence] = {}

    # Shape A: dict keyed by CVE ID
    if isinstance(data, dict) and any(str(k).startswith("CVE-") for k in data.keys()):
        for cve_id, payload in data.items():
            ids: List[str] = []
            if isinstance(payload, dict):
                raw_ids = payload.get("vulners_ids") or payload.get("ids") or payload.get(
                    "exploit_ids"
                )
                if isinstance(raw_ids, list):
                    ids = [str(x) for x in raw_ids if x]
                raw_refs = payload.get("references") or payload.get("exploits")
                if not ids and isinstance(raw_refs, list):
                    ids = [str(x) for x in raw_refs if x]
            out[str(cve_id)] = ExploitEvidence(flag=bool(ids), reference_count=len(ids), ids=ids)
        return out

    # Shape B: list of records that mention a single CVE
    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            cve_id = (item.get("cve_id") or item.get("cve") or "").strip()
            if not cve_id:
                continue
            ids: List[str] = []
            raw_ids = item.get("vulners_ids") or item.get("ids") or item.get("exploit_ids")
            if isinstance(raw_ids, list):
                ids = [str(x) for x in raw_ids if x]
            else:
                # Single id field
                rid = item.get("id") or item.get("vulners_id")
                if rid:
                    ids = [str(rid)]
            prev = out.get(cve_id)
            if prev:
                merged = sorted(set(prev.ids + ids))
                out[cve_id] = ExploitEvidence(
                    flag=bool(merged), reference_count=len(merged), ids=merged
                )
            else:
                out[cve_id] = ExploitEvidence(flag=bool(ids), reference_count=len(ids), ids=ids)
        return out

    # Unknown shape -> default empty
    return out


def _vulners_api_lookup_one(
    cve_id: str,
    api_key: str,
    timeout_s: int = 15,
    stats: Optional[VulnersApiStats] = None,
) -> ExploitEvidence:
    """Best-effort Vulners API lookup.

    Notes:
    - We call once per unique CVE ID.
    - Any failure returns empty evidence (never crashes the pipeline).
    """

    try:
        import requests  # type: ignore
    except Exception:
        return _empty_evidence()

    import time

    # Vulners APIs evolve; keep parsing defensive.
    # Use a query that tends to return exploit bulletins referencing the CVE.
    url = "https://vulners.com/api/v3/search/lucene/"
    payload = {
        "apiKey": api_key,
        # Common fields used by Vulners documents include cvelist; keep OR with cve:
        "query": f"cvelist:{cve_id} OR cve:{cve_id}",
        "size": 100,
    }

    if stats is not None:
        stats.calls_attempted += 1

    data: Any = None
    for attempt in range(3):
        try:
            resp = requests.post(url, json=payload, timeout=timeout_s)
            # Back off on rate limits/transient errors.
            if resp.status_code in (429, 500, 502, 503, 504):
                time.sleep(0.75 * (attempt + 1))
                continue
            if resp.status_code != 200:
                if stats is not None:
                    if resp.status_code == 403:
                        stats.http_403 += 1
                    elif resp.status_code == 429:
                        stats.http_429 += 1
                    else:
                        stats.http_other += 1
                return _empty_evidence()
            if stats is not None:
                stats.http_200 += 1
            data = resp.json()
            break
        except Exception:
            if stats is not None:
                stats.exceptions += 1
            time.sleep(0.5 * (attempt + 1))
            continue

    if not isinstance(data, dict):
        return _empty_evidence()

    # Extract doc-like records from a range of known/observed shapes.
    docs: List[Dict[str, Any]] = []
    inner = data.get("data")
    if isinstance(inner, dict):
        for key in ("search", "documents", "results", "items"):
            maybe = inner.get(key)
            if isinstance(maybe, list):
                docs.extend([d for d in maybe if isinstance(d, dict)])
        # Some shapes nest documents under a "documents" key with dicts.
        maybe_docs = inner.get("documents")
        if isinstance(maybe_docs, dict):
            for v in maybe_docs.values():
                if isinstance(v, dict):
                    docs.append(v)

    # Normalize doc extraction: Vulners search results sometimes wrap the real
    # document under a nested key.
    normalized_docs: List[Dict[str, Any]] = []
    for d in docs:
        if "_source" in d and isinstance(d.get("_source"), dict):
            nd = dict(d.get("_source"))
            # keep id if present on wrapper
            if "id" not in nd and d.get("_id"):
                nd["id"] = d.get("_id")
            normalized_docs.append(nd)
        elif "document" in d and isinstance(d.get("document"), dict):
            normalized_docs.append(dict(d.get("document")))
        else:
            normalized_docs.append(d)

    # Heuristic: treat exploit-related bulletin families/types as exploit evidence.
    exploit_families = {
        "exploit",
        "exploitdb",
        "metasploit",
        "packetstorm",
        "githubexploit",
        "0day",
        "attackerkb",
    }
    exploit_types = {
        "exploit",
        "exploitdb",
        "metasploit",
        "packetstorm",
        "githubexploit",
        "0day",
    }

    ids: List[str] = []
    for d in normalized_docs:
        if not isinstance(d, dict):
            continue
        dtype = (d.get("type") or d.get("_type") or "").strip().lower()
        family = (d.get("bulletinFamily") or d.get("bulletin_family") or "").strip().lower()
        did = d.get("id") or d.get("_id")
        if (dtype in exploit_types) or (family in exploit_families):
            if did:
                ids.append(str(did))

    ids = sorted(set(ids))
    return ExploitEvidence(flag=bool(ids), reference_count=len(ids), ids=ids)


def load_vulners_map(
    unique_cve_ids: Sequence[str],
    vulners_local_path: Optional[Path],
    vulners_api_key: Optional[str],
    stats: Optional[VulnersApiStats] = None,
) -> Dict[str, ExploitEvidence]:
    if vulners_local_path:
        return load_vulners_map_from_local(vulners_local_path)

    if not vulners_api_key:
        return {}

    out: Dict[str, ExploitEvidence] = {}
    for cve_id in unique_cve_ids:
        out[cve_id] = _vulners_api_lookup_one(cve_id, vulners_api_key, stats=stats)
    return out


# -------------------------
# ExploitDB (optional)
# -------------------------


def find_exploitdb_local_path() -> Optional[Path]:
    candidates = _resolve_candidates(
        [
            "exploitdb_data.json",
            "data/exploitdb_data.json",
            "product/data/exploitdb_data.json",
            "exploitdb_data.csv",
            "data/exploitdb_data.csv",
            "product/data/exploitdb_data.csv",
        ]
    )
    return _find_first_existing(candidates)


def _split_cve_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    s = str(value).strip()
    if not s:
        return []
    parts: List[str] = [s]
    for sep in [",", ";", "|", " "]:
        if sep in s:
            parts = [p.strip() for p in s.split(sep) if p.strip()]
            break
    return parts


def load_exploitdb_map(path: Path) -> Dict[str, ExploitEvidence]:
    """Load ExploitDB evidence from a local JSON or CSV export.

    We keep strict matching by CVE ID. If a row references multiple CVEs, we split
    and match exact CVE tokens.
    """

    out: Dict[str, ExploitEvidence] = {}

    if path.suffix.lower() == ".json":
        data = _read_json(path)

        records: List[Dict[str, Any]] = []
        if isinstance(data, list):
            records = [r for r in data if isinstance(r, dict)]
        elif isinstance(data, dict):
            # Either a dict keyed by CVE -> list, or a container with records.
            if any(str(k).startswith("CVE-") for k in data.keys()):
                for cve_id, v in data.items():
                    ids: List[str] = []
                    if isinstance(v, list):
                        ids = [str(x) for x in v if x]
                    elif isinstance(v, dict):
                        raw = v.get("ids") or v.get("exploit_ids")
                        if isinstance(raw, list):
                            ids = [str(x) for x in raw if x]
                    out[str(cve_id)] = ExploitEvidence(flag=bool(ids), reference_count=len(ids), ids=ids)
                return out
            records = [r for r in (data.get("records") or data.get("exploits") or []) if isinstance(r, dict)]

        for r in records:
            cve_field = r.get("cve_id") or r.get("cve") or r.get("cves")
            cves = _split_cve_list(cve_field)
            if not cves:
                continue
            rid = r.get("id") or r.get("exploit_id") or r.get("edb_id")
            ids = [str(rid)] if rid else []
            for cve_id in cves:
                prev = out.get(cve_id)
                if prev:
                    merged = sorted(set(prev.ids + ids))
                    out[cve_id] = ExploitEvidence(
                        flag=bool(merged), reference_count=len(merged), ids=merged
                    )
                else:
                    out[cve_id] = ExploitEvidence(
                        flag=bool(ids), reference_count=len(ids), ids=ids
                    )

        return out

    # CSV mode
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return out
        header_map = {_normalize_header(h): h for h in reader.fieldnames}

        def col(*names: str) -> Optional[str]:
            for n in names:
                key = _normalize_header(n)
                if key in header_map:
                    return header_map[key]
            return None

        cve_col = col("cve_id", "cve", "cves", "cveid")
        id_col = col("id", "exploit_id", "edb_id")
        if not cve_col:
            return out

        for row in reader:
            cves = _split_cve_list(row.get(cve_col))
            if not cves:
                continue
            rid = row.get(id_col) if id_col else None
            ids = [str(rid)] if rid else []
            for cve_id in cves:
                prev = out.get(cve_id)
                if prev:
                    merged = sorted(set(prev.ids + ids))
                    out[cve_id] = ExploitEvidence(
                        flag=bool(merged), reference_count=len(merged), ids=merged
                    )
                else:
                    out[cve_id] = ExploitEvidence(
                        flag=bool(ids), reference_count=len(ids), ids=ids
                    )

    return out


# -------------------------
# Enrichment
# -------------------------


def enrich_matches(
    matches: List[Dict[str, Any]],
    kev_map: Dict[str, Dict[str, Any]],
    epss_map: Dict[str, EPSSRecord],
    vulners_map: Dict[str, ExploitEvidence],
    exploitdb_map: Dict[str, ExploitEvidence],
) -> List[Dict[str, Any]]:
    enriched: List[Dict[str, Any]] = []

    for product in matches:
        product_out = dict(product)
        cves_in = product.get("matched_cves", []) or []
        cves_out: List[Dict[str, Any]] = []

        for cve in cves_in:
            if not isinstance(cve, dict):
                continue
            cve_id = (cve.get("cve_id") or "").strip()
            cve_out = dict(cve)

            # KEV
            kev = kev_map.get(cve_id)
            if kev:
                cve_out["kev_flag"] = True
                cve_out["kev_date_added"] = kev.get("kev_date_added")
            else:
                cve_out["kev_flag"] = False
                cve_out["kev_date_added"] = None

            # EPSS
            epss_rec = epss_map.get(cve_id)
            if epss_rec:
                cve_out["epss"] = float(epss_rec.epss)
                cve_out["epss_percentile"] = float(epss_rec.epss_percentile)
            else:
                cve_out["epss"] = 0.0
                cve_out["epss_percentile"] = 0.0

            # Vulners
            v = vulners_map.get(cve_id)
            if v:
                cve_out["vulners_exploit_flag"] = bool(v.flag)
                cve_out["vulners_reference_count"] = int(v.reference_count)
                cve_out["vulners_ids"] = list(v.ids)
            else:
                cve_out["vulners_exploit_flag"] = False
                cve_out["vulners_reference_count"] = 0
                cve_out["vulners_ids"] = []

            # ExploitDB
            e = exploitdb_map.get(cve_id)
            if e:
                cve_out["exploitdb_flag"] = bool(e.flag)
                cve_out["exploitdb_reference_count"] = int(e.reference_count)
                cve_out["exploitdb_ids"] = list(e.ids)
            else:
                cve_out["exploitdb_flag"] = False
                cve_out["exploitdb_reference_count"] = 0
                cve_out["exploitdb_ids"] = []

            cves_out.append(cve_out)

        product_out["matched_cves"] = cves_out
        enriched.append(product_out)

    return enriched


def _product_display_name(product: Dict[str, Any]) -> str:
    for k in ["display_product", "product_display", "display_name", "product_normalized"]:
        v = product.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return "(unknown_product)"


def print_summary(
    enriched: List[Dict[str, Any]],
    epss_map: Dict[str, EPSSRecord],
) -> None:
    products_processed = len(enriched)
    total_cves = 0
    kev_pos = 0
    epss_covered = 0
    vulners_pos = 0
    exploitdb_pos = 0

    for product in enriched:
        for c in product.get("matched_cves", []) or []:
            if not isinstance(c, dict):
                continue
            cve_id = (c.get("cve_id") or "").strip()
            if not cve_id:
                continue
            total_cves += 1
            if c.get("kev_flag") is True:
                kev_pos += 1
            if cve_id in epss_map:
                epss_covered += 1
            if c.get("vulners_exploit_flag") is True:
                vulners_pos += 1
            if c.get("exploitdb_flag") is True:
                exploitdb_pos += 1

    print("CVE enrichment summary")
    print("------------------------------")
    print(f"total products processed: {products_processed}")
    print(f"total matched CVEs processed: {total_cves}")
    print(f"KEV positives count: {kev_pos}")
    print(f"EPSS-covered CVEs count: {epss_covered}")
    print(f"Vulners positives count: {vulners_pos}")
    print(f"ExploitDB positives count: {exploitdb_pos}")

    print("\nPer-product breakdown")
    print("------------------------------")
    for product in enriched:
        cves = [c for c in (product.get("matched_cves", []) or []) if isinstance(c, dict)]
        if not cves:
            continue
        name = _product_display_name(product)
        matched_count = len(cves)
        kev_positive_count = sum(1 for c in cves if c.get("kev_flag") is True)
        exploit_evidence_count = sum(
            1
            for c in cves
            if (c.get("vulners_exploit_flag") is True) or (c.get("exploitdb_flag") is True)
        )
        print(f"{name} | {matched_count} | kev={kev_positive_count} | exploit_evidence={exploit_evidence_count}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Enrich matched CVEs with KEV/EPSS and optional exploit evidence."
    )
    parser.add_argument(
        "--matches",
        default=str(ROOT / "product" / "output" / "product_cve_matches.json"),
        help="Path to product_cve_matches.json (default: product/output/product_cve_matches.json)",
    )
    parser.add_argument(
        "--output",
        default=str(ROOT / "product" / "output" / "product_cve_enriched.json"),
        help="Output path (default: product/output/product_cve_enriched.json)",
    )

    args = parser.parse_args(list(argv) if argv is not None else None)

    matches_path = Path(args.matches)
    if not matches_path.is_absolute():
        matches_path = ROOT / matches_path

    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = ROOT / output_path

    if not matches_path.exists():
        print(f"ERROR: matches file not found: {matches_path}", file=sys.stderr)
        return 2

    matches = _read_json(matches_path)
    if not isinstance(matches, list):
        print(
            f"ERROR: expected matches JSON to be a list, got {type(matches)}",
            file=sys.stderr,
        )
        return 2

    unique_cve_ids = _collect_unique_cve_ids(matches)

    # Required inputs
    kev_path = find_kev_path()
    epss_path = find_epss_path()

    kev_map = load_kev_map(kev_path)
    epss_map = load_epss_map(epss_path)

    # Optional inputs
    vulners_local = find_vulners_local_path()
    vulners_api_key = os.environ.get("VULNERS_API_KEY")

    exploitdb_local = find_exploitdb_local_path()

    vulners_stats = VulnersApiStats() if (vulners_api_key and not vulners_local) else None
    vulners_map = load_vulners_map(
        unique_cve_ids,
        vulners_local,
        vulners_api_key,
        stats=vulners_stats,
    )

    exploitdb_map: Dict[str, ExploitEvidence] = {}
    if exploitdb_local:
        try:
            exploitdb_map = load_exploitdb_map(exploitdb_local)
        except Exception:
            exploitdb_map = {}

    enriched = enrich_matches(matches, kev_map, epss_map, vulners_map, exploitdb_map)
    _write_json(output_path, enriched)

    print_summary(enriched, epss_map)
    print(f"\nWrote: {output_path.relative_to(ROOT)}")

    if vulners_local:
        print(f"Vulners source: local ({vulners_local.relative_to(ROOT)})")
    elif vulners_api_key:
        print("Vulners source: API (VULNERS_API_KEY)")
        if vulners_stats is not None:
            print(
                "Vulners API stats: "
                f"calls={vulners_stats.calls_attempted}, "
                f"http_200={vulners_stats.http_200}, "
                f"http_403={vulners_stats.http_403}, "
                f"http_429={vulners_stats.http_429}, "
                f"http_other={vulners_stats.http_other}, "
                f"exceptions={vulners_stats.exceptions}"
            )
    else:
        print("Vulners source: none")

    if exploitdb_local:
        print(f"ExploitDB source: local ({exploitdb_local.relative_to(ROOT)})")
    else:
        print("ExploitDB source: none")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RequiredInputMissingError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        raise SystemExit(2)
