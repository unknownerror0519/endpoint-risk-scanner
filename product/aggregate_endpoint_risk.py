"""Final endpoint risk aggregation (one endpoint at a time).

Reads scored CVEs per installed application and aggregates:
- Level 1: CVE scores -> application risk (max CVE risk by default; also computes noisy-OR as diagnostic)
- Level 2: application risks -> endpoint risk (noisy-OR with exponent + dominance protection)

Hard rules:
- Use ALL scored CVEs across ALL matched applications (no top-N, no filtering)
- Deterministic formulas only
- Do not modify input files

Input:
- product/output/product_cve_scored.json

Output:
- product/output/endpoint_risk_summary.json (overwrite allowed)

Run:
  python product/aggregate_endpoint_risk.py
"""

from __future__ import annotations

import json
import math
import re
import statistics
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple


ROOT = Path(__file__).resolve().parents[1]


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


def _tier(score: float) -> str:
    score = float(score)
    if score >= 0.80:
        return "CRITICAL"
    if score >= 0.60:
        return "HIGH"
    if score >= 0.30:
        return "MODERATE"
    return "LOW"


def _tier_rank(t: str) -> int:
    return {"LOW": 0, "MODERATE": 1, "HIGH": 2, "CRITICAL": 3}.get(t, 0)


def _noisy_or(probs: List[float]) -> float:
    """Compute noisy-OR: 1 - Π(1 - p_i), with numeric stability.

    Inputs are assumed in [0, 1].
    """

    if not probs:
        return 0.0

    # If any p_i is 1.0, result is 1.0.
    for p in probs:
        if p >= 1.0:
            return 1.0

    # Use log-product: log(Π(1-p)) = Σ log(1-p)
    log_prod = 0.0
    for p in probs:
        p = _clamp01(float(p))
        # log1p(-p) is stable when p is small.
        log_prod += math.log1p(-p)

    prod = math.exp(log_prod)
    return _clamp01(1.0 - prod)


def _application_risk_from_cves(final_cve_risks: List[float]) -> float:
    """Application risk from CVEs.

    Note: `final_cve_risk` is a *risk score*, not a true independent probability.
    Using noisy-OR over large CVE counts quickly saturates to ~1.0 and becomes
    misleading. We therefore use a non-saturating default: max CVE risk.
    """

    if not final_cve_risks:
        return 0.0
    return _clamp01(max(_clamp01(float(x)) for x in final_cve_risks))


def _application_noisy_or_diagnostic(final_cve_risks: List[float]) -> float:
    """Noisy-OR over CVEs, kept for transparency/debugging only."""

    return _noisy_or([_clamp01(float(x)) for x in final_cve_risks])


def _endpoint_combined_risk(app_risks: List[float]) -> float:
    # endpoint_combined_risk = 1 - Π(1 - application_risk_score_i^1.5)
    adjusted = [(_clamp01(float(r)) ** 1.5) for r in app_risks]
    return _noisy_or(adjusted)


def _safe_float(value: Any) -> float:
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


_YEAR_RE = re.compile(r"\b(19\d{2}|20\d{2}|21\d{2})\b")


def _published_year(cve: Dict[str, Any]) -> int:
    raw = cve.get("published")
    if raw is None:
        return 0
    m = _YEAR_RE.search(str(raw))
    if not m:
        return 0
    try:
        return int(m.group(1))
    except ValueError:
        return 0


def _cvss_base_score(cve: Dict[str, Any]) -> float:
    # Preferred: explicit parsed CVSS v3 object from enrichment.
    cvss_v3 = cve.get("cvss_v3")
    if isinstance(cvss_v3, dict):
        s = cvss_v3.get("baseScore")
        if s is not None:
            return _safe_float(s)

    # Fallback: some pipelines may store it at top-level.
    for key in ("cvss", "cvss_score", "cvss_v3_score"):
        if key in cve:
            return _safe_float(cve.get(key))

    return 0.0


def _is_high_confidence_cpe_match(cve: Dict[str, Any]) -> bool:
    src = str(cve.get("match_source") or "").lower()
    conf = str(cve.get("match_confidence") or "").lower()
    return (src == "cpe" or "cpe" in src) and conf == "high"


def aggregate_endpoint(scored_products: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate product-level scored CVEs into application and endpoint risk."""

    application_summaries: List[Dict[str, Any]] = []

    total_cve_count = 0
    total_kev_count = 0
    total_exploit_evidence_count = 0
    application_count_with_cves = 0

    # Level 1: CVE -> application
    for product in scored_products:
        if not isinstance(product, dict):
            continue

        cves = product.get("matched_cves", []) or []
        cves = [c for c in cves if isinstance(c, dict)]

        display_product = product.get("display_product") or product.get("product_display") or product.get("product_normalized") or ""
        vendor_normalized = product.get("vendor_normalized") or ""
        product_normalized = product.get("product_normalized") or ""
        version_normalized = product.get("version_normalized")

        final_risks = [_clamp01(_safe_float(c.get("final_cve_risk"))) for c in cves]

        matched_cve_count = int(len(cves))
        if matched_cve_count > 0:
            application_count_with_cves += 1

        application_risk_score = _application_risk_from_cves(final_risks)
        application_noisy_or_risk = _application_noisy_or_diagnostic(final_risks)

        # Severity override (conservative): if the app has *recent* critical-severity CVEs
        # (CVSS >= 9.0) matched via high-confidence CPE evidence, don't allow the app to
        # remain LOW/MODERATE purely because exploit-signal features are absent.
        current_year = datetime.now().year
        recent_year_cutoff = current_year - 1  # includes current year and previous year
        has_recent_critical_cvss = any(
            (
                _published_year(c) >= recent_year_cutoff
                and _cvss_base_score(c) >= 9.0
                and _is_high_confidence_cpe_match(c)
            )
            for c in cves
        )
        if has_recent_critical_cvss:
            application_risk_score = max(float(application_risk_score), 0.80)

        application_risk_tier = _tier(application_risk_score)

        max_cve_risk = max(final_risks) if final_risks else 0.0
        mean_cve_risk = float(statistics.fmean(final_risks)) if final_risks else 0.0

        kev_cve_count = sum(1 for c in cves if bool(c.get("kev_flag")))
        exploit_evidence_count = sum(
            1
            for c in cves
            if bool(c.get("vulners_exploit_flag")) or bool(c.get("exploitdb_flag"))
        )

        total_cve_count += matched_cve_count
        total_kev_count += kev_cve_count
        total_exploit_evidence_count += exploit_evidence_count

        application_summaries.append(
            {
                "display_product": str(display_product),
                "vendor_normalized": str(vendor_normalized),
                "product_normalized": str(product_normalized),
                "version_normalized": version_normalized,
                "matched_cve_count": matched_cve_count,
                "application_risk_score": float(_clamp01(application_risk_score)),
                "application_risk_score_0_100": float(round(_clamp01(application_risk_score) * 100.0, 2)),
                "application_risk_tier": application_risk_tier,
                "application_noisy_or_risk": float(_clamp01(application_noisy_or_risk)),
                "max_cve_risk": float(_clamp01(max_cve_risk)),
                "mean_cve_risk": float(_clamp01(mean_cve_risk)),
                "kev_cve_count": int(kev_cve_count),
                "exploit_evidence_count": int(exploit_evidence_count),
            }
        )

    # Sort application summaries by risk desc, then matched_cve_count desc
    application_summaries.sort(
        key=lambda r: (
            float(r.get("application_risk_score", 0.0)),
            int(r.get("matched_cve_count", 0)),
        ),
        reverse=True,
    )

    app_risks = [float(r["application_risk_score"]) for r in application_summaries]

    # Level 2: application -> endpoint
    if not app_risks:
        endpoint_combined_risk = 0.0
        max_application_risk = 0.0
        mean_application_risk = 0.0
        endpoint_risk_score = 0.0
    else:
        endpoint_combined_risk = _endpoint_combined_risk(app_risks)
        max_application_risk = max(app_risks)
        mean_application_risk = float(statistics.fmean(app_risks))
        endpoint_risk_score = max(max_application_risk, endpoint_combined_risk)

    endpoint_combined_risk = float(_clamp01(endpoint_combined_risk))
    max_application_risk = float(_clamp01(max_application_risk))
    mean_application_risk = float(_clamp01(mean_application_risk))
    endpoint_risk_score = float(_clamp01(endpoint_risk_score))

    endpoint_risk_tier = _tier(endpoint_risk_score)

    endpoint_summary = {
        "endpoint_risk_score": endpoint_risk_score,
        "endpoint_risk_score_0_100": float(round(endpoint_risk_score * 100.0, 2)),
        "endpoint_combined_risk": endpoint_combined_risk,
        "endpoint_combined_risk_0_100": float(round(endpoint_combined_risk * 100.0, 2)),
        "max_application_risk": max_application_risk,
        "max_application_risk_0_100": float(round(max_application_risk * 100.0, 2)),
        "endpoint_risk_tier": endpoint_risk_tier,
        "mean_application_risk": mean_application_risk,
        "mean_application_risk_0_100": float(round(mean_application_risk * 100.0, 2)),
        "application_count_total": int(len(application_summaries)),
        "application_count_with_cves": int(application_count_with_cves),
        "total_cve_count": int(total_cve_count),
        "total_kev_count": int(total_kev_count),
        "total_exploit_evidence_count": int(total_exploit_evidence_count),
    }

    return {
        "endpoint_summary": endpoint_summary,
        "application_summaries": application_summaries,
    }


def _load_scored_products(input_path: Path) -> List[Dict[str, Any]]:
    data = _read_json(input_path)
    if not isinstance(data, list):
        raise ValueError("Expected product_cve_scored.json to be a list")
    return [x for x in data if isinstance(x, dict)]


def main() -> int:
    input_path = ROOT / "product" / "output" / "product_cve_scored.json"
    output_path = ROOT / "product" / "output" / "endpoint_risk_summary.json"

    scored_products = _load_scored_products(input_path)
    result = aggregate_endpoint(scored_products)

    _write_json(output_path, result)

    # Print summary
    es = result["endpoint_summary"]

    print("Endpoint risk summary")
    print("------------------------------")
    print(f"application_count_with_cves: {es['application_count_with_cves']}")
    print(f"total_cve_count: {es['total_cve_count']}")
    print(f"total_kev_count: {es['total_kev_count']}")
    print(f"total_exploit_evidence_count: {es['total_exploit_evidence_count']}")
    print(f"endpoint_combined_risk: {es['endpoint_combined_risk']:.6f}")
    print(f"max_application_risk: {es['max_application_risk']:.6f}")
    print(f"endpoint_risk_score: {es['endpoint_risk_score']:.6f}")
    print(f"endpoint_risk_tier: {es['endpoint_risk_tier']}")

    print("\nPer-application summaries")
    print("------------------------------")
    for app in result["application_summaries"]:
        print(
            f"{app.get('display_product','')} | {app.get('version_normalized')} | "
            f"{app.get('matched_cve_count',0)} | {float(app.get('application_risk_score',0.0)):.6f} | {app.get('application_risk_tier','LOW')}"
        )

    # Print full output JSON contents (required)
    print("\nFull output: product/output/endpoint_risk_summary.json")
    print("------------------------------")
    print(json.dumps(result, ensure_ascii=False, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
