from __future__ import annotations

from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd


TRAIN_IN = Path("data/train_dataset_features.csv")
TEST_IN = Path("data/test_dataset_features.csv")

TRAIN_OUT = Path("data/train_dataset_features_v4.csv")
TEST_OUT = Path("data/test_dataset_features_v4.csv")


EPSS_CANDIDATES = [
    Path("epss_scores"),
    Path("epss_scores.csv"),
    Path("data/epss_scores"),
    Path("data/epss_scores.csv"),
]


def _find_existing_path(candidates: list[Path]) -> Path:
    for path in candidates:
        if path.exists() and path.is_file():
            return path
    tried = "\n".join(str(p) for p in candidates)
    raise FileNotFoundError(f"EPSS file not found. Tried these paths:\n{tried}")


def _pick_column(df: pd.DataFrame, candidates: list[str]) -> Optional[str]:
    cols_lower = {c.lower(): c for c in df.columns}
    for name in candidates:
        if name.lower() in cols_lower:
            return cols_lower[name.lower()]
    return None


def _normalize_cve_id(series: pd.Series) -> pd.Series:
    s = series.fillna("").astype(str).str.strip().str.upper()

    # If values are like 2024-1234, prefix CVE-
    looks_like_suffix = s.str.match(r"^\d{4}-\d{1,}$")
    s = s.where(~looks_like_suffix, "CVE-" + s)

    return s


def _coerce_unit_interval(series: pd.Series) -> pd.Series:
    vals = pd.to_numeric(series, errors="coerce")
    vals = vals.where((vals >= 0.0) & (vals <= 1.0))
    return vals


def load_epss(epss_path: Path) -> pd.DataFrame:
    try:
        epss_df = pd.read_csv(epss_path, comment="#")
    except Exception:
        epss_df = pd.read_csv(
            epss_path,
            comment="#",
            engine="python",
            on_bad_lines="skip",
        )

    cve_col = _pick_column(epss_df, ["cve", "cve_id", "CVE", "cveID"])
    if cve_col is None:
        raise ValueError(
            "EPSS file is missing a CVE column (expected one of: cve, cve_id, CVE, cveID)"
        )
    epss_df = epss_df.rename(columns={cve_col: "cve_id"})
    epss_df["cve_id"] = _normalize_cve_id(epss_df["cve_id"])

    epss_col = _pick_column(epss_df, ["epss", "EPSS", "epss_score"])
    if epss_col is None:
        raise ValueError(
            "EPSS file is missing an EPSS probability column (expected one of: epss, EPSS, epss_score)"
        )
    epss_df = epss_df.rename(columns={epss_col: "epss"})
    epss_df["epss"] = _coerce_unit_interval(epss_df["epss"])

    percentile_col = _pick_column(
        epss_df, ["percentile", "epss_percentile", "EPSS Percentile"]
    )
    if percentile_col is not None and percentile_col != "epss_percentile":
        epss_df = epss_df.rename(columns={percentile_col: "epss_percentile"})

    if "epss_percentile" in epss_df.columns:
        epss_df["epss_percentile"] = _coerce_unit_interval(epss_df["epss_percentile"])

    keep_cols = ["cve_id", "epss"] + (["epss_percentile"] if "epss_percentile" in epss_df.columns else [])
    epss_df = epss_df[keep_cols]

    # Keep the last occurrence per CVE if duplicates exist
    epss_df = epss_df.dropna(subset=["cve_id"])
    epss_df = epss_df.drop_duplicates(subset=["cve_id"], keep="last")

    return epss_df


def merge_epss(features_df: pd.DataFrame, epss_df: pd.DataFrame) -> pd.DataFrame:
    if "cve_id" not in features_df.columns:
        raise ValueError("Feature dataset is missing required column: cve_id")

    df = features_df.copy()
    df["cve_id"] = _normalize_cve_id(df["cve_id"])

    merged = df.merge(epss_df, on="cve_id", how="left")

    merged["epss"] = pd.to_numeric(merged["epss"], errors="coerce").fillna(0.0)
    if "epss_percentile" in merged.columns:
        merged["epss_percentile"] = (
            pd.to_numeric(merged["epss_percentile"], errors="coerce").fillna(0.0)
        )

    return merged


def main() -> None:
    epss_path = _find_existing_path(EPSS_CANDIDATES)
    epss_df = load_epss(epss_path)

    train_df = pd.read_csv(TRAIN_IN)
    test_df = pd.read_csv(TEST_IN)

    train_v4 = merge_epss(train_df, epss_df)
    test_v4 = merge_epss(test_df, epss_df)

    train_v4.to_csv(TRAIN_OUT, index=False)
    test_v4.to_csv(TEST_OUT, index=False)

    # Verification output
    print(f"EPSS rows count: {len(epss_df)}")
    print(f"Unique EPSS CVEs count: {epss_df['cve_id'].nunique()}")
    print(f"Train rows count: {len(train_v4)}")
    print(f"Test rows count: {len(test_v4)}")

    train_cov = int((train_v4["epss"] > 0).sum())
    test_cov = int((test_v4["epss"] > 0).sum())
    print(f"Train EPSS coverage (epss > 0): {train_cov}")
    print(f"Test EPSS coverage (epss > 0): {test_cov}")

    cols = ["cve_id", "epss"]
    if "epss_percentile" in train_v4.columns:
        cols.append("epss_percentile")
    cols.append("label")

    print("First 5 rows preview:")
    print(train_v4[cols].head(5).to_string(index=False))


if __name__ == "__main__":
    main()
