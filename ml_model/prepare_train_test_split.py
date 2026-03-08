from __future__ import annotations

import re

import numpy as np
import pandas as pd


INPUT_CSV = "data/training_dataset.csv"
TRAIN_OUT = "data/train_dataset.csv"
TEST_OUT = "data/test_dataset.csv"


_whitespace_re = re.compile(r"\s+")
_answer_prefix_re = re.compile(r"^\s*Answer:\s*")


def clean_description(text: str) -> str:
    """Clean NVD description text without removing meaningful security terms.

    Rules:
    1) Remove literal prefix "Answer:" if it appears at the beginning.
    2) Replace newline characters with a single space.
    3) Collapse multiple whitespace into a single space.
    4) Strip leading/trailing whitespace.
    """
    if text is None:
        return ""

    # Preserve non-string types (e.g., NaN) safely
    if isinstance(text, float) and np.isnan(text):
        return ""

    if not isinstance(text, str):
        text = str(text)

    # Remove a leading "Answer:" prefix even if preceded by whitespace,
    # and remove any whitespace immediately after the prefix.
    text = _answer_prefix_re.sub("", text, count=1)

    # Replace newlines with spaces
    text = text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")

    # Collapse any whitespace runs (spaces/tabs/etc.) to single spaces
    text = _whitespace_re.sub(" ", text)

    return text.strip()


def main() -> None:
    df = pd.read_csv(INPUT_CSV)

    # Clean description column (in-place)
    if "description" not in df.columns:
        raise ValueError("Missing required column: description")
    df["description"] = df["description"].map(clean_description)

    # Parse published -> datetime and derive year
    if "published" not in df.columns:
        raise ValueError("Missing required column: published")

    published_dt = pd.to_datetime(df["published"], errors="coerce")
    df["year"] = published_dt.dt.year

    # Drop rows only if published cannot be parsed (cannot be assigned to a time split)
    missing_year_mask = df["year"].isna()
    missing_year_count = int(missing_year_mask.sum())
    if missing_year_count:
        df = df.loc[~missing_year_mask].copy()

    df["year"] = df["year"].astype(int)

    # Ensure label is numeric 0/1
    if "label" not in df.columns:
        raise ValueError("Missing required column: label")
    df["label"] = pd.to_numeric(df["label"], errors="coerce").fillna(0).astype(int)

    # Leakage-safe temporal split (no shuffle)
    train_df = df.loc[df["year"] <= 2022].copy()
    test_df = df.loc[df["year"] >= 2023].copy()

    # Save outputs
    train_df.to_csv(TRAIN_OUT, index=False)
    test_df.to_csv(TEST_OUT, index=False)

    # Reporting
    total_rows = int(len(df))
    positives = int((df["label"] == 1).sum())
    negatives = int((df["label"] == 0).sum())

    train_size = int(len(train_df))
    test_size = int(len(test_df))

    train_pos_rate = float((train_df["label"] == 1).mean()) if train_size else 0.0
    test_pos_rate = float((test_df["label"] == 1).mean()) if test_size else 0.0

    print(f"Total dataset rows: {total_rows}")
    print(f"Positive samples (label=1): {positives}")
    print(f"Negative samples (label=0): {negatives}")
    print(f"Training set size (year <= 2022): {train_size}")
    print(f"Test set size (year >= 2023): {test_size}")
    print(f"Positive rate in train set: {train_pos_rate:.6f}")
    print(f"Positive rate in test set: {test_pos_rate:.6f}")

    if missing_year_count:
        print(f"Rows dropped due to unparseable published -> year: {missing_year_count}")


if __name__ == "__main__":
    main()
