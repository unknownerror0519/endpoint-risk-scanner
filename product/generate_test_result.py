import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _safe_float(x: Any, default: float = 0.0) -> float:
    try:
        return float(x)
    except Exception:
        return default


def _shorten(text: str, max_len: int = 140) -> str:
    text = (text or "").strip().replace("\n", " ")
    if len(text) <= max_len:
        return text
    return text[: max_len - 1].rstrip() + "…"


def _product_key(p: Dict[str, Any]) -> Tuple[str, str, str]:
    return (
        (p.get("vendor_normalized") or "").strip(),
        (p.get("product_normalized") or "").strip(),
        (p.get("version_normalized") or "").strip(),
    )


def _iter_scored_cves(scored_products: List[Dict[str, Any]]) -> Iterable[Tuple[Dict[str, Any], Dict[str, Any]]]:
    for product in scored_products:
        for cve in product.get("matched_cves") or []:
            yield product, cve


def _pick_reference(cve: Dict[str, Any]) -> Optional[str]:
    refs = cve.get("references") or []
    if isinstance(refs, list):
        for r in refs:
            if isinstance(r, str) and r.startswith("https://"):
                return r
        for r in refs:
            if isinstance(r, str) and r.startswith("http://"):
                return r
    return None


def _tier_sort_key(tier: str) -> int:
    order = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3}
    return order.get((tier or "").upper(), 99)


def generate_report(
    *,
    doc_id: str,
    inventory_path: Path,
    scored_path: Path,
    endpoint_summary_path: Path,
    output_path: Path,
    top_apps: int,
    top_cves_per_app: int,
    top_cves_overall: int,
) -> None:
    inventory = _load_json(inventory_path)
    scored_products = _load_json(scored_path)
    endpoint = _load_json(endpoint_summary_path)

    endpoint_summary = endpoint.get("endpoint_summary") or {}
    app_summaries = endpoint.get("application_summaries") or []

    inventory_count = len(inventory) if isinstance(inventory, list) else 0
    product_count = len(scored_products) if isinstance(scored_products, list) else 0

    matched_products = [p for p in (scored_products or []) if (p.get("matched_cve_count") or 0) > 0]

    tier_counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MODERATE": 0, "LOW": 0}
    all_cves: List[Dict[str, Any]] = []
    kev_cves: List[Dict[str, Any]] = []

    for product, cve in _iter_scored_cves(scored_products or []):
        tier = (cve.get("risk_tier") or "").upper()
        if tier in tier_counts:
            tier_counts[tier] += 1
        else:
            tier_counts[tier] = tier_counts.get(tier, 0) + 1

        enriched = dict(cve)
        enriched["_product"] = {
            "display_product": product.get("display_product"),
            "vendor_normalized": product.get("vendor_normalized"),
            "product_normalized": product.get("product_normalized"),
            "version_normalized": product.get("version_normalized"),
        }
        all_cves.append(enriched)
        if cve.get("kev_flag") is True:
            kev_cves.append(enriched)

    all_cves.sort(key=lambda c: _safe_float(c.get("final_cve_risk")), reverse=True)

    # Map product -> list of CVEs sorted by risk
    per_product_top: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
    for product in matched_products:
        key = _product_key(product)
        cves = list(product.get("matched_cves") or [])
        cves.sort(key=lambda c: _safe_float(c.get("final_cve_risk")), reverse=True)
        per_product_top[key] = cves

    generated_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")

    output_path.parent.mkdir(parents=True, exist_ok=True)

    lines: List[str] = []
    lines.append("# Endpoint CVE Scan Report")
    lines.append("")
    lines.append(f"- Firestore doc id: `{doc_id}`")
    lines.append(f"- Generated at (UTC): `{generated_at}`")
    lines.append("")

    lines.append("## Artifact Paths")
    lines.append("")
    lines.append(f"- Inventory: `{inventory_path.as_posix()}`")
    lines.append(f"- Scored CVEs: `{scored_path.as_posix()}`")
    lines.append(f"- Endpoint summary: `{endpoint_summary_path.as_posix()}`")
    lines.append("")

    lines.append("## Inventory")
    lines.append("")
    lines.append(f"- Normalized products: **{inventory_count}**")
    lines.append(f"- Products processed in scoring: **{product_count}**")
    lines.append(f"- Products with matched CVEs: **{len(matched_products)}**")
    lines.append("")

    lines.append("## Endpoint Risk")
    lines.append("")
    endpoint_score = _safe_float(endpoint_summary.get("endpoint_risk_score"))
    lines.append(f"- Endpoint risk score: **{endpoint_score * 100.0:.2f}/100** ({endpoint_score:.6f})")
    lines.append(f"- Endpoint risk tier: **{endpoint_summary.get('endpoint_risk_tier', 'UNKNOWN')}**")
    lines.append(f"- Total matched CVEs: **{endpoint_summary.get('total_cve_count', 0)}**")
    lines.append(f"- Total KEV CVEs: **{endpoint_summary.get('total_kev_count', 0)}**")
    lines.append(f"- Exploit evidence count: **{endpoint_summary.get('total_exploit_evidence_count', 0)}**")
    lines.append("")

    lines.append("## CVE Tier Counts")
    lines.append("")
    lines.append(f"- CRITICAL: **{tier_counts.get('CRITICAL', 0)}**")
    lines.append(f"- HIGH: **{tier_counts.get('HIGH', 0)}**")
    lines.append(f"- MODERATE: **{tier_counts.get('MODERATE', 0)}**")
    lines.append(f"- LOW: **{tier_counts.get('LOW', 0)}**")
    lines.append("")

    # Applications
    lines.append("## Top Applications (by application risk)")
    lines.append("")
    app_summaries_sorted = list(app_summaries)
    app_summaries_sorted.sort(key=lambda a: _safe_float(a.get("application_risk_score")), reverse=True)
    for app in app_summaries_sorted[: max(0, top_apps)]:
        app_score = _safe_float(app.get("application_risk_score"))
        lines.append(
            "- "
            + f"{app.get('display_product', 'Unknown')} {app.get('version_normalized', '')}".strip()
            + f" — risk **{app_score * 100.0:.2f}/100** ({app_score:.6f}; {app.get('application_risk_tier', 'UNKNOWN')})"
            + f"; CVEs **{app.get('matched_cve_count', 0)}**; KEV **{app.get('kev_cve_count', 0)}**"
        )
    lines.append("")

    # Top CVEs overall
    lines.append(f"## Top {top_cves_overall} CVEs (overall)")
    lines.append("")
    for cve in all_cves[: max(0, top_cves_overall)]:
        ref = _pick_reference(cve)
        ref_part = f" ({ref})" if ref else ""
        prod = cve.get("_product") or {}
        cve_score = _safe_float(cve.get("final_cve_risk"))
        lines.append(
            "- "
            + f"{cve.get('cve_id')} — risk **{cve_score * 100.0:.2f}/100** ({cve_score:.4f}; {cve.get('risk_tier')})"
            + f"; EPSS {_safe_float(cve.get('epss')):.4f}; KEV {bool(cve.get('kev_flag'))}"
            + f"; {prod.get('display_product', 'Unknown')}{ref_part}\n"
            + f"  - {_shorten(cve.get('description') or '')}"
        )
    lines.append("")

    # KEV CVEs
    kev_cves_sorted = list(kev_cves)
    kev_cves_sorted.sort(
        key=lambda c: (
            _tier_sort_key(c.get("risk_tier") or ""),
            -_safe_float(c.get("final_cve_risk")),
        )
    )
    lines.append("## KEV CVEs")
    lines.append("")
    if not kev_cves_sorted:
        lines.append("- None")
    else:
        for cve in kev_cves_sorted:
            prod = cve.get("_product") or {}
            cve_score = _safe_float(cve.get("final_cve_risk"))
            lines.append(
                "- "
                + f"{cve.get('cve_id')} — {prod.get('display_product', 'Unknown')}"
                + f"; risk **{cve_score * 100.0:.2f}/100** ({cve_score:.4f}; {cve.get('risk_tier')})"
                + f"; date_added {cve.get('kev_date_added') or 'Unknown'}"
            )
    lines.append("")

    # Per-app CVEs for top risky apps
    lines.append(f"## Top CVEs Per Application (top {top_cves_per_app})")
    lines.append("")
    for app in app_summaries_sorted[: max(0, top_apps)]:
        app_key = (
            (app.get("vendor_normalized") or "").strip(),
            (app.get("product_normalized") or "").strip(),
            (app.get("version_normalized") or "").strip(),
        )
        cves = per_product_top.get(app_key) or []
        if not cves:
            continue
        lines.append(f"### {app.get('display_product', 'Unknown')} {app.get('version_normalized', '')}".strip())
        lines.append("")
        for cve in cves[: max(0, top_cves_per_app)]:
            cve_score = _safe_float(cve.get("final_cve_risk"))
            lines.append(
                "- "
                + f"{cve.get('cve_id')} — risk **{cve_score * 100.0:.2f}/100** ({cve_score:.4f}; {cve.get('risk_tier')})"
                + f"; EPSS {_safe_float(cve.get('epss')):.4f}; KEV {bool(cve.get('kev_flag'))}"
            )
        lines.append("")

    # Notes
    any_vulners = any((_safe_float(c.get("vulners_reference_count"), 0.0) > 0) for _, c in _iter_scored_cves(scored_products or []))
    lines.append("## Notes")
    lines.append("")
    if any_vulners:
        lines.append("- Vulners evidence: present in output")
    else:
        lines.append("- Vulners evidence: none in output (in some environments Vulners API calls can be blocked by Cloudflare; pipeline remains valid without it)")

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a human-readable endpoint CVE scan report.")
    parser.add_argument("--doc-id", required=True, help="Firestore document id for the endpoint")
    parser.add_argument(
        "--inventory",
        default=str(Path("product/output/output_inventory.json")),
        help="Path to inventory JSON",
    )
    parser.add_argument(
        "--scored",
        default=str(Path("product/output/product_cve_scored.json")),
        help="Path to scored CVEs JSON",
    )
    parser.add_argument(
        "--endpoint-summary",
        default=str(Path("product/output/endpoint_risk_summary.json")),
        help="Path to endpoint risk summary JSON",
    )
    parser.add_argument(
        "--output",
        default=str(Path("product/output/test_result.md")),
        help="Output report path (.md or .txt)",
    )
    parser.add_argument("--top-apps", type=int, default=10)
    parser.add_argument("--top-cves-per-app", type=int, default=10)
    parser.add_argument("--top-cves-overall", type=int, default=20)

    args = parser.parse_args()

    generate_report(
        doc_id=args.doc_id,
        inventory_path=Path(args.inventory),
        scored_path=Path(args.scored),
        endpoint_summary_path=Path(args.endpoint_summary),
        output_path=Path(args.output),
        top_apps=args.top_apps,
        top_cves_per_app=args.top_cves_per_app,
        top_cves_overall=args.top_cves_overall,
    )

    print(f"Wrote: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
