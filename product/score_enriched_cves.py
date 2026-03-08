"""Per-CVE scoring stage (one endpoint at a time).

Reads enriched CVEs for installed products and:
1) Generates the exact ML feature vector expected by the v4 pipeline.
2) Loads the calibrated XGBoost v4 model artifact (supports two artifact shapes).
3) Computes ML probability for each CVE.
4) Combines ML probability with live enrichment signals to compute a dynamic
   final CVE risk score.

Hard rules:
- Do NOT retrain models
- Do NOT modify input files
- Do NOT aggregate to app/endpoint level
- Deterministic feature generation
- Robust to missing optional CVSS/CWE fields

Inputs:
- product/output/product_cve_enriched.json
- models/xgboost_model_v4_calibrated.pkl
- models/onehot_encoder_v4.pkl

Output:
- product/output/product_cve_scored.json

Run:
  python product/score_enriched_cves.py
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np
import pandas as pd
from joblib import load


ROOT = Path(__file__).resolve().parents[1]


NUMERIC_COLS = [
    "cvss_score",
    "nlp_rce",
    "nlp_priv_esc",
    "nlp_dos",
    "nlp_zero_day",
    "high_risk_cwe",
    "epss",
    "epss_percentile",
]

CATEGORICAL_COLS = [
    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "confidentiality",
    "integrity",
    "availability",
    "cwe",
]

# High-risk CWE set used by the v4 feature engineering code.
HIGH_RISK_CWES = {
    "CWE-79",
    "CWE-89",
    "CWE-119",
    "CWE-78",
    "CWE-20",
    "CWE-22",
    "CWE-125",
    "CWE-787",
}


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _find_model_path(rel: str) -> Path:
    """Resolve a model artifact path.

    Spec path is ROOT/models/<rel>. We also support a safe fallback to
    ROOT/ml_model/models/<rel> if present.
    """

    primary = ROOT / "models" / rel
    fallback = ROOT / "ml_model" / "models" / rel

    if primary.exists():
        return primary
    if fallback.exists():
        return fallback

    raise FileNotFoundError(
        f"Model artifact not found: {primary} (or fallback {fallback})"
    )


# -----------------------------
# Feature generation
# -----------------------------


def _compile_any(phrases: List[str]) -> re.Pattern[str]:
    escaped = [re.escape(p) for p in phrases]
    return re.compile("(?:" + "|".join(escaped) + ")", flags=re.IGNORECASE)


_PAT_RCE = _compile_any(
    [
        "remote code execution",
        "execute arbitrary code",
        "execute arbitrary commands",
        "command injection",
        "arbitrary command execution",
    ]
)

_PAT_PRIV_ESC = _compile_any(
    [
        "privilege escalation",
        "elevation of privilege",
        "gain root privileges",
        "gain administrative privileges",
    ]
)

# Use word boundaries for short tokens.
_PAT_DOS = re.compile(
    r"(?:denial\s+of\s+service|\bdos\b|service\s+crash|system\s+crash)",
    flags=re.IGNORECASE,
)

_PAT_ZERO_DAY = re.compile(
    r"(?:zero-day|zero\s+day|\b0day\b|in\s+the\s+wild|actively\s+exploited)",
    flags=re.IGNORECASE,
)


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


def _normalize_cwe(value: Any) -> str:
    s = str(value or "").strip()
    if not s:
        return "UNKNOWN"
    # Keep canonical CWE-XXX form when present.
    m = re.search(r"CWE-\d+", s, flags=re.IGNORECASE)
    if m:
        return m.group(0).upper()
    return s


def _cvss_from_enriched_cve(cve: Dict[str, Any]) -> Tuple[float, Dict[str, str]]:
    """Extract cvss_score and categorical CVSS attributes.

    Our enrichment output carries a cvss_v3 object with a CVSS v3.x vector string.
    Training used NVD cvssData fields like attackVector='NETWORK', etc.

    If missing, return (0.0, all UNKNOWN).
    """

    unknowns = {
        "attack_vector": "UNKNOWN",
        "attack_complexity": "UNKNOWN",
        "privileges_required": "UNKNOWN",
        "user_interaction": "UNKNOWN",
        "confidentiality": "UNKNOWN",
        "integrity": "UNKNOWN",
        "availability": "UNKNOWN",
    }

    cvss_obj = cve.get("cvss_v3")
    if not isinstance(cvss_obj, dict):
        return 0.0, unknowns

    score = _safe_float(cvss_obj.get("baseScore"))
    vector = str(cvss_obj.get("vectorString") or "").strip()
    if not vector:
        return score, unknowns

    # Parse tokens like AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H
    tokens: Dict[str, str] = {}
    for part in vector.split("/"):
        if ":" not in part:
            continue
        k, v = part.split(":", 1)
        tokens[k.strip().upper()] = v.strip().upper()

    av = tokens.get("AV")
    ac = tokens.get("AC")
    pr = tokens.get("PR")
    ui = tokens.get("UI")
    c = tokens.get("C")
    i = tokens.get("I")
    a = tokens.get("A")

    def map_av(x: Optional[str]) -> str:
        return {
            "N": "NETWORK",
            "A": "ADJACENT_NETWORK",
            "L": "LOCAL",
            "P": "PHYSICAL",
        }.get(x or "", "UNKNOWN")

    def map_bin(x: Optional[str]) -> str:
        return {"L": "LOW", "H": "HIGH"}.get(x or "", "UNKNOWN")

    def map_pr(x: Optional[str]) -> str:
        return {"N": "NONE", "L": "LOW", "H": "HIGH"}.get(x or "", "UNKNOWN")

    def map_ui(x: Optional[str]) -> str:
        return {"N": "NONE", "R": "REQUIRED"}.get(x or "", "UNKNOWN")

    def map_impact(x: Optional[str]) -> str:
        return {"N": "NONE", "L": "LOW", "H": "HIGH"}.get(x or "", "UNKNOWN")

    cats = {
        "attack_vector": map_av(av),
        "attack_complexity": map_bin(ac),
        "privileges_required": map_pr(pr),
        "user_interaction": map_ui(ui),
        "confidentiality": map_impact(c),
        "integrity": map_impact(i),
        "availability": map_impact(a),
    }
    return score, cats


def _nlp_flags(description: Any) -> Tuple[int, int, int, int]:
    text = str(description or "")
    nlp_rce = 1 if _PAT_RCE.search(text) else 0
    nlp_priv_esc = 1 if _PAT_PRIV_ESC.search(text) else 0
    nlp_dos = 1 if _PAT_DOS.search(text) else 0
    nlp_zero_day = 1 if _PAT_ZERO_DAY.search(text) else 0
    return nlp_rce, nlp_priv_esc, nlp_dos, nlp_zero_day


def _build_feature_row(cve: Dict[str, Any]) -> Tuple[np.ndarray, Dict[str, Any]]:
    """Return (numeric_array, categorical_dict) for one CVE."""

    cvss_score, cvss_cats = _cvss_from_enriched_cve(cve)

    epss = _safe_float(cve.get("epss"))
    epss_percentile = _safe_float(cve.get("epss_percentile"))

    nlp_rce, nlp_priv_esc, nlp_dos, nlp_zero_day = _nlp_flags(cve.get("description"))

    cwe = _normalize_cwe(cve.get("cwe"))
    high_risk_cwe = 1 if cwe in HIGH_RISK_CWES else 0

    numeric = np.array(
        [
            float(cvss_score),
            float(nlp_rce),
            float(nlp_priv_esc),
            float(nlp_dos),
            float(nlp_zero_day),
            float(high_risk_cwe),
            float(epss),
            float(epss_percentile),
        ],
        dtype=np.float32,
    )

    cats: Dict[str, Any] = {
        **cvss_cats,
        "cwe": cwe if cwe else "UNKNOWN",
    }

    # Ensure all categorical fields exist
    for k in CATEGORICAL_COLS:
        v = cats.get(k)
        cats[k] = str(v).strip().upper() if v else "UNKNOWN"

    return numeric, cats


def _encode_features(
    numeric: np.ndarray,
    cats: Dict[str, Any],
    encoder: Any,
) -> np.ndarray:
    df = pd.DataFrame([{k: cats.get(k, "UNKNOWN") for k in CATEGORICAL_COLS}])
    # Mirror v4 prep: missing -> UNKNOWN (already enforced)
    X_cat = encoder.transform(df[CATEGORICAL_COLS])
    if hasattr(X_cat, "toarray"):
        X_cat = X_cat.toarray()
    X_cat = np.asarray(X_cat, dtype=np.float32)

    X_num = np.asarray(numeric, dtype=np.float32).reshape(1, -1)
    X = np.hstack([X_num, X_cat]).astype(np.float32, copy=False)
    return X


# -----------------------------
# Model scoring
# -----------------------------


@dataclass(frozen=True)
class ModelBundle:
    kind: str  # 'direct' or 'dict'
    model: Any
    base_model: Any
    calibrator: Any


def _load_calibrated_model(path: Path) -> ModelBundle:
    artifact = load(path)

    # Option B: directly callable calibrated model with predict_proba
    if hasattr(artifact, "predict_proba"):
        return ModelBundle(kind="direct", model=artifact, base_model=None, calibrator=None)

    # Option A: dict with base_model + isotonic_calibrator
    if isinstance(artifact, dict):
        base_model = artifact.get("base_model")
        calibrator = artifact.get("isotonic_calibrator")
        if base_model is None or calibrator is None:
            raise ValueError(
                "Calibrated model dict missing base_model or isotonic_calibrator"
            )
        return ModelBundle(kind="dict", model=None, base_model=base_model, calibrator=calibrator)

    raise TypeError(
        "Unsupported calibrated model artifact type. Expected predict_proba model or dict."
    )


def _predict_ml_probability(bundle: ModelBundle, X_row: np.ndarray) -> float:
    if bundle.kind == "direct":
        proba = bundle.model.predict_proba(X_row)[:, 1][0]
        return float(proba)

    # bundle.kind == 'dict'
    if not hasattr(bundle.base_model, "predict_proba"):
        raise TypeError("base_model does not support predict_proba")
    raw = float(bundle.base_model.predict_proba(X_row)[:, 1][0])

    cal = bundle.calibrator
    if hasattr(cal, "transform"):
        out = cal.transform([raw])
        return float(out[0])
    if hasattr(cal, "predict"):
        out = cal.predict([raw])
        return float(out[0])

    raise TypeError("Unsupported isotonic calibrator (no transform/predict)")


def _clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


def _risk_tier(score: float) -> str:
    if score >= 0.80:
        return "CRITICAL"
    if score >= 0.60:
        return "HIGH"
    if score >= 0.30:
        return "MODERATE"
    return "LOW"


def _tier_rank(t: str) -> int:
    return {"LOW": 0, "MODERATE": 1, "HIGH": 2, "CRITICAL": 3}.get(t, 0)


def _score_one_cve(cve: Dict[str, Any], encoder: Any, model_bundle: ModelBundle) -> Dict[str, Any]:
    numeric, cats = _build_feature_row(cve)
    X_row = _encode_features(numeric, cats, encoder)
    ml_probability = _predict_ml_probability(model_bundle, X_row)

    cvss_score, _ = _cvss_from_enriched_cve(cve)
    cvss_norm = _clamp01(float(cvss_score) / 10.0)

    epss = _safe_float(cve.get("epss"))
    kev_bonus = 1.0 if bool(cve.get("kev_flag")) else 0.0
    vulners_bonus = 1.0 if bool(cve.get("vulners_exploit_flag")) else 0.0
    exploitdb_bonus = 1.0 if bool(cve.get("exploitdb_flag")) else 0.0

    # Risk formula: severity baseline (CVSS) + exploitation signals.
    # CVSS provides a severity floor so that high-severity CVEs
    # always receive a meaningful risk score even without exploit
    # evidence; ML and EPSS boost the score when exploitation is
    # likely.
    final_cve_risk = (
        0.30 * float(ml_probability)
        + 0.25 * cvss_norm
        + 0.15 * float(epss)
        + 0.15 * float(kev_bonus)
        + 0.10 * float(vulners_bonus)
        + 0.05 * float(exploitdb_bonus)
    )
    final_cve_risk = _clamp01(float(final_cve_risk))

    out = dict(cve)
    out["ml_exploit_probability"] = float(_clamp01(float(ml_probability)))
    out["ml_probability"] = out["ml_exploit_probability"]  # backward compat
    out["cvss_severity_norm"] = float(cvss_norm)
    out["kev_bonus"] = float(kev_bonus)
    out["vulners_bonus"] = float(vulners_bonus)
    out["exploitdb_bonus"] = float(exploitdb_bonus)
    out["final_cve_risk"] = float(final_cve_risk)
    out["final_cve_risk_0_100"] = float(round(final_cve_risk * 100.0, 2))
    out["risk_tier"] = _risk_tier(final_cve_risk)
    return out


# -----------------------------
# Main
# -----------------------------


def score_endpoint(
    enriched_path: Path,
    model_path: Path,
    encoder_path: Path,
    output_path: Path,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    enriched = _read_json(enriched_path)
    if not isinstance(enriched, list):
        raise ValueError("Expected enriched JSON to be a list")

    encoder = load(encoder_path)
    model_bundle = _load_calibrated_model(model_path)

    tier_counts = {"CRITICAL": 0, "HIGH": 0, "MODERATE": 0, "LOW": 0}
    total_scored = 0

    scored_products: List[Dict[str, Any]] = []
    per_product_lines: List[Tuple[str, int, float, str]] = []

    for product in enriched:
        if not isinstance(product, dict):
            continue

        product_out = dict(product)
        cves = product.get("matched_cves", []) or []
        scored_cves: List[Dict[str, Any]] = []

        for cve in cves:
            if not isinstance(cve, dict):
                continue
            scored = _score_one_cve(cve, encoder, model_bundle)
            scored_cves.append(scored)
            total_scored += 1
            tier_counts[scored["risk_tier"]] = tier_counts.get(scored["risk_tier"], 0) + 1

        product_out["matched_cves"] = scored_cves
        # Preserve grouping fields; keep matched_cve_count consistent.
        product_out["matched_cve_count"] = int(len(scored_cves))
        scored_products.append(product_out)

        if scored_cves:
            name = str(product.get("display_product") or product.get("product_display") or product.get("product_normalized") or "(unknown)")
            max_risk = max(float(c.get("final_cve_risk") or 0.0) for c in scored_cves)
            top_tier = "LOW"
            for c in scored_cves:
                t = str(c.get("risk_tier") or "LOW")
                if _tier_rank(t) > _tier_rank(top_tier):
                    top_tier = t
            per_product_lines.append((name, len(scored_cves), float(max_risk), top_tier))

    _write_json(output_path, scored_products)

    summary = {
        "total_products_processed": int(len(scored_products)),
        "total_cves_scored": int(total_scored),
        "tier_counts": tier_counts,
        "per_product": per_product_lines,
    }
    return scored_products, summary


def main(argv: Optional[Sequence[str]] = None) -> int:
    # Fixed paths per requirements.
    enriched_path = ROOT / "product" / "output" / "product_cve_enriched.json"
    output_path = ROOT / "product" / "output" / "product_cve_scored.json"

    model_path = _find_model_path("xgboost_model_v4_calibrated.pkl")
    encoder_path = _find_model_path("onehot_encoder_v4.pkl")

    scored, summary = score_endpoint(
        enriched_path=enriched_path,
        model_path=model_path,
        encoder_path=encoder_path,
        output_path=output_path,
    )

    # Print summary
    tier = summary["tier_counts"]
    print("CVE scoring summary")
    print("------------------------------")
    print(f"total products processed: {summary['total_products_processed']}")
    print(f"total CVEs scored: {summary['total_cves_scored']}")
    print("risk tier counts")
    print(f"critical: {tier.get('CRITICAL', 0)}")
    print(f"high: {tier.get('HIGH', 0)}")
    print(f"moderate: {tier.get('MODERATE', 0)}")
    print(f"low: {tier.get('LOW', 0)}")

    print("\nPer-product breakdown")
    print("------------------------------")
    for name, count, max_risk, top_tier in summary["per_product"]:
        print(f"{name} | {count} | max_final_cve_risk={max_risk:.4f} | top_risk_tier={top_tier}")

    # Keep output signal minimal
    print(f"\nWrote: {output_path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
