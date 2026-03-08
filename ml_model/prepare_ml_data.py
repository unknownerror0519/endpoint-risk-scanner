from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.preprocessing import OneHotEncoder


TRAIN_CSV = "data/train_dataset_features.csv"
TEST_CSV = "data/test_dataset_features.csv"

OUT_X_TRAIN = "data/X_train.npy"
OUT_X_TEST = "data/X_test.npy"
OUT_Y_TRAIN = "data/y_train.npy"
OUT_Y_TEST = "data/y_test.npy"


FEATURES = [
    "cvss_score",
    "attack_vector",
    "attack_complexity",
    "privileges_required",
    "user_interaction",
    "confidentiality",
    "integrity",
    "availability",
    "cwe",
    "nlp_rce",
    "nlp_priv_esc",
    "nlp_dos",
    "nlp_zero_day",
    "high_risk_cwe",
]

LABEL_COL = "label"

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

NUMERIC_COLS = [
    "cvss_score",
    "nlp_rce",
    "nlp_priv_esc",
    "nlp_dos",
    "nlp_zero_day",
    "high_risk_cwe",
]


def main() -> None:
    train_df = pd.read_csv(TRAIN_CSV)
    test_df = pd.read_csv(TEST_CSV)

    missing_features = [c for c in FEATURES if c not in train_df.columns or c not in test_df.columns]
    if missing_features:
        raise ValueError(f"Missing required feature columns: {missing_features}")
    if LABEL_COL not in train_df.columns or LABEL_COL not in test_df.columns:
        raise ValueError(f"Missing required label column: {LABEL_COL}")

    X_train_df = train_df[FEATURES].copy()
    y_train = train_df[LABEL_COL].to_numpy(dtype=np.int64)

    X_test_df = test_df[FEATURES].copy()
    y_test = test_df[LABEL_COL].to_numpy(dtype=np.int64)

    # Fill missing values safely
    for col in CATEGORICAL_COLS:
        X_train_df[col] = X_train_df[col].fillna("UNKNOWN").astype(str)
        X_test_df[col] = X_test_df[col].fillna("UNKNOWN").astype(str)

    for col in NUMERIC_COLS:
        X_train_df[col] = pd.to_numeric(X_train_df[col], errors="coerce").fillna(0)
        X_test_df[col] = pd.to_numeric(X_test_df[col], errors="coerce").fillna(0)

    # Encode categoricals: fit on train only, transform train+test
    ohe = OneHotEncoder(handle_unknown="ignore", sparse_output=False, dtype=np.float32)
    X_train_cat = ohe.fit_transform(X_train_df[CATEGORICAL_COLS])
    X_test_cat = ohe.transform(X_test_df[CATEGORICAL_COLS])

    # Numeric arrays
    X_train_num = X_train_df[NUMERIC_COLS].to_numpy(dtype=np.float32, copy=True)
    X_test_num = X_test_df[NUMERIC_COLS].to_numpy(dtype=np.float32, copy=True)

    # Combine
    X_train = np.hstack([X_train_num, X_train_cat]).astype(np.float32, copy=False)
    X_test = np.hstack([X_test_num, X_test_cat]).astype(np.float32, copy=False)

    # Save
    np.save(OUT_X_TRAIN, X_train)
    np.save(OUT_X_TEST, X_test)
    np.save(OUT_Y_TRAIN, y_train)
    np.save(OUT_Y_TEST, y_test)

    print(f"Training samples count: {X_train.shape[0]}")
    print(f"Test samples count: {X_test.shape[0]}")
    print(f"Final number of features after encoding: {X_train.shape[1]}")


if __name__ == "__main__":
    main()
