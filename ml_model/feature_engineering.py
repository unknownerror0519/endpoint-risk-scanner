from __future__ import annotations

import re

import numpy as np
import pandas as pd


TRAIN_PATH = "data/train_dataset.csv"
TEST_PATH = "data/test_dataset.csv"

TRAIN_OUT = "data/train_dataset_features.csv"
TEST_OUT = "data/test_dataset_features.csv"


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


def _compile_any(phrases: list[str]) -> re.Pattern[str]:
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
    ]
)

# Use word boundaries for short tokens to avoid accidental matches inside other words.
_PAT_DOS = re.compile(r"(?:denial\s+of\s+service|\bdos\b)", flags=re.IGNORECASE)
_PAT_ZERO_DAY = re.compile(r"(?:zero\s+day|\b0day\b)", flags=re.IGNORECASE)


def _add_nlp_features(df: pd.DataFrame) -> pd.DataFrame:
    if "description" not in df.columns:
        raise ValueError("Missing required column: description")

    desc = df["description"].fillna("").astype(str)

    df = df.copy()
    df["nlp_rce"] = desc.str.contains(_PAT_RCE, regex=True).astype(np.int8)
    df["nlp_priv_esc"] = desc.str.contains(_PAT_PRIV_ESC, regex=True).astype(np.int8)
    df["nlp_dos"] = desc.str.contains(_PAT_DOS, regex=True).astype(np.int8)
    df["nlp_zero_day"] = desc.str.contains(_PAT_ZERO_DAY, regex=True).astype(np.int8)
    df["high_risk_cwe"] = df["cwe"].isin(HIGH_RISK_CWES).astype(np.int8)
    return df


def main() -> None:
    train_df = pd.read_csv(TRAIN_PATH)
    test_df = pd.read_csv(TEST_PATH)

    train_df = _add_nlp_features(train_df)
    test_df = _add_nlp_features(test_df)

    # Print counts (combined across train+test)
    for col in ("nlp_rce", "nlp_priv_esc", "nlp_dos", "nlp_zero_day"):
        count = int(train_df[col].sum() + test_df[col].sum())
        print(f"{col} count: {count}")

    high_risk_cwe_count = int(train_df["high_risk_cwe"].sum() + test_df["high_risk_cwe"].sum())
    print(f"high_risk_cwe count: {high_risk_cwe_count}")

    train_df.to_csv(TRAIN_OUT, index=False)
    test_df.to_csv(TEST_OUT, index=False)


if __name__ == "__main__":
    main()
