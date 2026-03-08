"""Endpoint scan orchestrator (safe wrapper for web app integration).

SAFETY RULES
- This script is an orchestrator only.
- It does NOT modify/overwrite any existing pipeline scripts.
- It does NOT overwrite any existing output JSONs.
- It writes all outputs into a new per-scan folder under: product/output/scans/

It reuses existing pipeline logic by:
- Running scripts that support --output into the scan folder.
- Importing and calling functions for scripts that have fixed output paths.

Outputs written (inside the scan folder):
- output_inventory.json
- product_cve_matches.json
- product_cve_enriched.json
- product_cve_scored.json
- endpoint_risk_summary.json
- product_cve_dynamic_scored.json
- test_result.md
- endpoint_scan_bundle.json

Run example:
  C:/Users/YASINDU/AppData/Local/Programs/Python/Python314/python.exe product/run_endpoint_scan.py \
    --firestore-service-account product/secrets/serviceAccountKey.json \
    --firestore-doc-id 3ee54ea0-135b-5c7c-c249-e4b35fdeec4b
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, Optional, Sequence, Tuple


ROOT = Path(__file__).resolve().parents[1]


def _utc_stamp() -> str:
    # Safe for folder names.
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d_%H%M%SZ")


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _run_step(args: Sequence[str], *, label: str) -> None:
    """Run a subprocess step and fail fast with good diagnostics."""

    print(f"\n== {label} ==")
    print(" ".join(str(a) for a in args))

    proc = subprocess.run(
        list(args),
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    if proc.stdout:
        print(proc.stdout.rstrip())
    if proc.returncode != 0:
        if proc.stderr:
            print(proc.stderr.rstrip(), file=sys.stderr)
        raise RuntimeError(f"Step failed ({label}) with exit code {proc.returncode}")


def _load_module_from_path(module_name: str, file_path: Path) -> ModuleType:
    """Load a Python module from an explicit file path.

    This avoids requiring `product/` to be a Python package.
    """

    spec = importlib.util.spec_from_file_location(module_name, str(file_path))
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load module spec for: {file_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _score_enriched_to_scored(enriched_path: Path, scored_path: Path) -> Tuple[Dict[str, Any], Path, Path]:
    """Call scoring logic in-process to allow custom paths without overwriting global outputs."""

    scorer = _load_module_from_path(
        "_score_enriched_cves",
        ROOT / "product" / "score_enriched_cves.py",
    )

    model_path = scorer._find_model_path("xgboost_model_v4_calibrated.pkl")
    encoder_path = scorer._find_model_path("onehot_encoder_v4.pkl")

    _, summary = scorer.score_endpoint(
        enriched_path=enriched_path,
        model_path=model_path,
        encoder_path=encoder_path,
        output_path=scored_path,
    )
    return summary, model_path, encoder_path


def _aggregate_scored_to_endpoint(scored_path: Path, endpoint_summary_path: Path) -> Dict[str, Any]:
    """Call aggregation logic in-process to allow custom paths."""

    aggregator = _load_module_from_path(
        "_aggregate_endpoint_risk",
        ROOT / "product" / "aggregate_endpoint_risk.py",
    )

    scored_products = _read_json(scored_path)
    if not isinstance(scored_products, list):
        raise ValueError("Scored products JSON must be a list")

    result = aggregator.aggregate_endpoint(scored_products)
    _write_json(endpoint_summary_path, result)
    return result


def _make_scan_dir(doc_id: str, base_dir: Optional[Path] = None) -> Path:
    base = base_dir or (ROOT / "product" / "output" / "scans")
    safe_doc = "".join(c for c in doc_id if c.isalnum() or c in ("-", "_")) or "endpoint"
    run_dir = base / safe_doc / _utc_stamp()
    run_dir.mkdir(parents=True, exist_ok=False)
    return run_dir


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run a full endpoint scan into a per-scan output folder.")

    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--endpoint-json", help="Path to endpoint JSON (must contain applications array)")
    src.add_argument(
        "--firestore-service-account",
        help="Path to service account key JSON (read-only Firestore access)",
    )

    parser.add_argument("--firestore-collection", default="endpoint data")
    parser.add_argument("--firestore-doc-id", default=None)
    parser.add_argument("--firestore-project-id", default=None)

    parser.add_argument(
        "--endpoint-platform",
        default=None,
        choices=["windows", "macos", "linux", "unknown"],
        help="Optional override for platform filtering during CVE mapping",
    )

    parser.add_argument(
        "--min-cve-year",
        type=int,
        default=None,
        help="Optional minimum CVE published year to consider (inclusive) during matching.",
    )
    parser.add_argument(
        "--max-cve-year",
        type=int,
        default=None,
        help="Optional maximum CVE published year to consider (inclusive) during matching.",
    )

    parser.add_argument(
        "--scan-dir",
        default=None,
        help="Optional base scan directory (default: product/output/scans)",
    )

    parser.add_argument(
        "--doc-id",
        default=None,
        help=(
            "Endpoint doc id label used in reports. If Firestore is used and --firestore-doc-id is provided, "
            "it will be used automatically."
        ),
    )

    args = parser.parse_args(list(argv) if argv is not None else None)

    python = sys.executable

    # Determine doc id label.
    doc_id = args.doc_id or args.firestore_doc_id or "endpoint"

    scan_base = Path(args.scan_dir) if args.scan_dir else None
    scan_dir = _make_scan_dir(doc_id, scan_base)

    inventory_path = scan_dir / "output_inventory.json"
    matches_path = scan_dir / "product_cve_matches.json"
    enriched_path = scan_dir / "product_cve_enriched.json"
    scored_path = scan_dir / "product_cve_scored.json"
    endpoint_summary_path = scan_dir / "endpoint_risk_summary.json"
    dynamic_scored_path = scan_dir / "product_cve_dynamic_scored.json"
    report_path = scan_dir / "test_result.md"
    bundle_path = scan_dir / "endpoint_scan_bundle.json"

    # 1) Build inventory (subprocess; supports --output)
    if args.endpoint_json:
        _run_step(
            [
                python,
                str(ROOT / "product" / "build_product_inventory.py"),
                "--input",
                args.endpoint_json,
                "--output",
                str(inventory_path),
            ],
            label="Build inventory",
        )
    else:
        if not args.firestore_doc_id:
            raise ValueError("--firestore-doc-id is required when using --firestore-service-account")
        _run_step(
            [
                python,
                str(ROOT / "product" / "build_product_inventory.py"),
                "--firestore-service-account",
                args.firestore_service_account,
                "--firestore-collection",
                args.firestore_collection,
                "--firestore-doc-id",
                args.firestore_doc_id,
                "--output",
                str(inventory_path),
            ]
            + (["--firestore-project-id", args.firestore_project_id] if args.firestore_project_id else []),
            label="Fetch endpoint + build inventory",
        )

    # 2) Map products -> CVEs (subprocess; supports --inventory/--output)
    map_cmd = [
        python,
        str(ROOT / "product" / "map_products_to_cves.py"),
        "--inventory",
        str(inventory_path),
        "--output",
        str(matches_path),
    ]
    if args.endpoint_platform:
        map_cmd += ["--endpoint-platform", args.endpoint_platform]
    if args.min_cve_year is not None:
        map_cmd += ["--min-cve-year", str(int(args.min_cve_year))]
    if args.max_cve_year is not None:
        map_cmd += ["--max-cve-year", str(int(args.max_cve_year))]
    _run_step(map_cmd, label="Map products to CVEs")

    # 3) Enrich (subprocess; supports --matches/--output)
    _run_step(
        [
            python,
            str(ROOT / "product" / "enrich_matched_cves.py"),
            "--matches",
            str(matches_path),
            "--output",
            str(enriched_path),
        ],
        label="Enrich matched CVEs",
    )

    # 4) Score enriched CVEs (in-process; custom paths)
    print("\n== Score CVEs ==")
    scoring_summary, model_path, encoder_path = _score_enriched_to_scored(enriched_path, scored_path)
    print(
        "CVE scoring summary: "
        f"products={scoring_summary.get('total_products_processed')}, "
        f"cves={scoring_summary.get('total_cves_scored')}"
    )
    print(f"Model: {model_path}")
    print(f"Encoder: {encoder_path}")
    print(f"Wrote: {scored_path}")

    # 5) Aggregate endpoint risk (in-process; custom paths)
    print("\n== Aggregate endpoint risk ==")
    endpoint_result = _aggregate_scored_to_endpoint(scored_path, endpoint_summary_path)
    es = endpoint_result.get("endpoint_summary") or {}
    print(
        "Endpoint: "
        f"risk={es.get('endpoint_risk_score_0_100', round(float(es.get('endpoint_risk_score', 0.0)) * 100.0, 2))}/100 "
        f"tier={es.get('endpoint_risk_tier', 'UNKNOWN')}"
    )
    print(f"Wrote: {endpoint_summary_path}")

    # 6) Dynamic CVE risk layer (subprocess; supports --input/--output)
    _run_step(
        [
            python,
            str(ROOT / "product" / "dynamic_cve_risk.py"),
            "--input",
            str(scored_path),
            "--output",
            str(dynamic_scored_path),
        ],
        label="Dynamic CVE risk scoring",
    )

    # 7) Human-readable report (subprocess; supports custom paths)
    _run_step(
        [
            python,
            str(ROOT / "product" / "generate_test_result.py"),
            "--doc-id",
            doc_id,
            "--inventory",
            str(inventory_path),
            "--scored",
            str(scored_path),
            "--endpoint-summary",
            str(endpoint_summary_path),
            "--output",
            str(report_path),
        ],
        label="Generate report",
    )

    # 8) Bundle JSON for the web app
    bundle = {
        "doc_id": doc_id,
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "scan_dir": str(scan_dir.relative_to(ROOT)),
        "artifacts": {
            "inventory": str(inventory_path.relative_to(ROOT)),
            "matches": str(matches_path.relative_to(ROOT)),
            "enriched": str(enriched_path.relative_to(ROOT)),
            "scored": str(scored_path.relative_to(ROOT)),
            "endpoint_summary": str(endpoint_summary_path.relative_to(ROOT)),
            "dynamic_scored": str(dynamic_scored_path.relative_to(ROOT)),
            "report_md": str(report_path.relative_to(ROOT)),
        },
        "endpoint_summary": (endpoint_result.get("endpoint_summary") or {}),
        "application_summaries": (endpoint_result.get("application_summaries") or []),
    }
    _write_json(bundle_path, bundle)
    print("\n== Done ==")
    print(f"Scan folder: {scan_dir.relative_to(ROOT)}")
    print(f"Bundle: {bundle_path.relative_to(ROOT)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
