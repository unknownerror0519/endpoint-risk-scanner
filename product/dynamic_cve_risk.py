"""Research-grade dynamic CVE risk layer (safe extension).

SAFETY GUARANTEE
- Reads:  product/output/product_cve_scored.json
- Writes: product/output/product_cve_dynamic_scored.json
- Does NOT modify any existing scripts, model artifacts, or input files.

This script appends dynamic risk fields inside each CVE entry (matched_cves)
while keeping the overall JSON structure identical.

Run:
  C:/Users/YASINDU/AppData/Local/Programs/Python/Python314/python.exe product/dynamic_cve_risk.py

Optional:
  ... --input product/output/product_cve_scored.json --output product/output/product_cve_dynamic_scored.json
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


ROOT = Path(__file__).resolve().parents[1]


def _clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


def _safe_float(value: Any, default: float = 0.0) -> float:
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return float(value)
    s = str(value).strip()
    if not s:
        return default
    try:
        return float(s)
    except ValueError:
        return default


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _parse_date_like(value: Any) -> Optional[dt.date]:
    """Parse a date/datetime string robustly and return a date.

    Handles values like:
    - 2021-03-11T16:15:13.863
    - 2021-03-11T16:15:13.863Z
    - 2021-03-11
    - 2021-03-11T16:15:13
    """

    if not value:
        return None

    if isinstance(value, dt.date) and not isinstance(value, dt.datetime):
        return value

    if isinstance(value, dt.datetime):
        return value.date()

    s = str(value).strip()
    if not s:
        return None

    # Normalize common ISO variants.
    if s.endswith("Z"):
        s = s[:-1]

    # Try full ISO parsing first.
    try:
        # dt.datetime.fromisoformat supports 'YYYY-MM-DD' and 'YYYY-MM-DDTHH:MM:SS[.ffffff]'
        parsed_dt = dt.datetime.fromisoformat(s)
        return parsed_dt.date()
    except ValueError:
        pass

    # Try a few explicit formats.
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            parsed_dt = dt.datetime.strptime(s, fmt)
            return parsed_dt.date()
        except ValueError:
            continue

    # As a last resort, try to take the date prefix.
    if len(s) >= 10:
        prefix = s[:10]
        try:
            return dt.datetime.strptime(prefix, "%Y-%m-%d").date()
        except ValueError:
            return None

    return None


def _temporal_factor(days_since_cve: int) -> float:
    days = max(0, int(days_since_cve))
    denom = math.log(365)
    if denom <= 0:
        return 0.0
    return min(1.0, math.log1p(days) / denom)


def _kev_recency_factor(days_since_kev: Optional[int]) -> float:
    if days_since_kev is None:
        return 0.0
    d = max(0, int(days_since_kev))
    # exp(-days / 60)
    return float(math.exp(-float(d) / 60.0))


def _dynamic_risk_tier(score: float) -> str:
    score = float(score)
    if score >= 0.80:
        return "SEVERE"
    if score >= 0.60:
        return "HIGH"
    if score >= 0.30:
        return "MODERATE"
    return "LOW"


def _score_cve(cve: Dict[str, Any], today: dt.date) -> Dict[str, Any]:
    """Return a *new* CVE dict with dynamic fields appended."""

    published_date = _parse_date_like(cve.get("published"))
    if published_date is None:
        days_since_cve = 0
    else:
        days_since_cve = max(0, (today - published_date).days)

    temporal = _temporal_factor(days_since_cve)

    p_ml = _clamp01(_safe_float(cve.get("ml_probability"), 0.0))
    s_epss = _clamp01(_safe_float(cve.get("epss"), 0.0))
    s_kev = 1.0 if bool(cve.get("kev_flag")) else 0.0

    exploit_signal = 0.0
    if bool(cve.get("vulners_exploit_flag")):
        exploit_signal += 0.5
    if bool(cve.get("exploitdb_flag")):
        exploit_signal += 0.5
    exploit_signal = min(1.0, exploit_signal)

    kev_recency = 0.0
    if bool(cve.get("kev_flag")):
        kev_added = _parse_date_like(cve.get("kev_date_added"))
        if kev_added is not None:
            days_since_kev = max(0, (today - kev_added).days)
            kev_recency = _kev_recency_factor(days_since_kev)
        else:
            kev_recency = 0.0

    dynamic = (
        p_ml
        * (1.0 + 0.6 * s_epss)
        * (1.0 + 0.5 * s_kev)
        * (1.0 + 0.4 * exploit_signal)
        * (1.0 + 0.25 * temporal)
        * (1.0 + 0.2 * kev_recency)
    )
    dynamic = _clamp01(float(dynamic))

    out = dict(cve)
    out["dynamic_cve_risk"] = float(dynamic)
    out["dynamic_risk_tier"] = _dynamic_risk_tier(dynamic)
    out["days_since_cve"] = int(days_since_cve)
    out["temporal_factor"] = float(temporal)
    out["exploit_signal"] = float(exploit_signal)
    out["kev_recency_factor"] = float(kev_recency)
    return out


def _iter_cves(products: List[Dict[str, Any]]) -> Sequence[Tuple[str, Dict[str, Any]]]:
    """Yield (product_name, cve_dict) for summary printing."""

    rows: List[Tuple[str, Dict[str, Any]]] = []
    for product in products:
        if not isinstance(product, dict):
            continue
        name = str(product.get("display_product") or product.get("product_display") or product.get("product_normalized") or "")
        for cve in product.get("matched_cves") or []:
            if isinstance(cve, dict):
                rows.append((name, cve))
    return rows


def dynamic_score_file(input_path: Path, output_path: Path) -> None:
    data = _read_json(input_path)
    if not isinstance(data, list):
        raise ValueError("Expected input JSON to be a list of products")

    today = dt.datetime.now(dt.timezone.utc).date()

    output_products: List[Dict[str, Any]] = []

    for product in data:
        if not isinstance(product, dict):
            continue

        out_product = dict(product)
        cves = product.get("matched_cves") or []
        if isinstance(cves, list):
            out_cves: List[Dict[str, Any]] = []
            for cve in cves:
                if not isinstance(cve, dict):
                    continue
                out_cves.append(_score_cve(cve, today))
            out_product["matched_cves"] = out_cves
        output_products.append(out_product)

    _write_json(output_path, output_products)

    # Summary stats
    scored_rows = _iter_cves(output_products)
    total_cves = len(scored_rows)

    if total_cves == 0:
        print("Dynamic CVE risk summary")
        print("------------------------------")
        print("Total CVEs processed: 0")
        print("Average dynamic CVE risk: 0.000000")
        print("Number of SEVERE CVEs: 0")
        print("Number of HIGH CVEs: 0")
        print("Number of MODERATE CVEs: 0")
        print("Number of LOW CVEs: 0")
        print("\nTop 10 CVEs by dynamic risk: none")
        print(f"\nWrote: {output_path}")
        return

    risks = [float(cve.get("dynamic_cve_risk") or 0.0) for _, cve in scored_rows]
    avg_risk = sum(risks) / float(len(risks))

    tier_counts = {"SEVERE": 0, "HIGH": 0, "MODERATE": 0, "LOW": 0}
    for _, cve in scored_rows:
        tier = str(cve.get("dynamic_risk_tier") or "LOW")
        tier_counts[tier] = tier_counts.get(tier, 0) + 1

    top10 = sorted(
        scored_rows,
        key=lambda row: float(row[1].get("dynamic_cve_risk") or 0.0),
        reverse=True,
    )[:10]

    print("Dynamic CVE risk summary")
    print("------------------------------")
    print(f"Total CVEs processed: {total_cves}")
    print(f"Average dynamic CVE risk: {avg_risk:.6f}")
    print(f"Number of SEVERE CVEs: {tier_counts.get('SEVERE', 0)}")
    print(f"Number of HIGH CVEs: {tier_counts.get('HIGH', 0)}")
    print(f"Number of MODERATE CVEs: {tier_counts.get('MODERATE', 0)}")
    print(f"Number of LOW CVEs: {tier_counts.get('LOW', 0)}")

    print("\nTop 10 CVEs by dynamic risk")
    print("------------------------------")
    for product_name, cve in top10:
        cve_id = cve.get("cve_id") or "UNKNOWN"
        dyn = float(cve.get("dynamic_cve_risk") or 0.0)
        tier = cve.get("dynamic_risk_tier") or "LOW"
        epss = _safe_float(cve.get("epss"), 0.0)
        kev = bool(cve.get("kev_flag"))
        print(f"{cve_id} | {dyn:.6f} | {tier} | EPSS={epss:.4f} | KEV={kev} | {product_name}")

    print(f"\nWrote: {output_path}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Add a research-grade dynamic CVE risk layer (safe, read-only inputs).")
    parser.add_argument(
        "--input",
        default=str(ROOT / "product" / "output" / "product_cve_scored.json"),
        help="Input scored CVE file (product_cve_scored.json)",
    )
    parser.add_argument(
        "--output",
        default=str(ROOT / "product" / "output" / "product_cve_dynamic_scored.json"),
        help="Output file (product_cve_dynamic_scored.json)",
    )

    args = parser.parse_args(argv)
    input_path = Path(args.input)
    output_path = Path(args.output)

    dynamic_score_file(input_path, output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
