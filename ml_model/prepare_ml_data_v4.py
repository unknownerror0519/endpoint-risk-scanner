from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
from joblib import dump
from sklearn.preprocessing import OneHotEncoder


TRAIN_CSV = "data/train_dataset_features_v4.csv"
TEST_CSV = "data/test_dataset_features_v4.csv"

X_TRAIN_OUT = "data/X_train_v4.npy"
X_TEST_OUT = "data/X_test_v4.npy"
Y_TRAIN_OUT = "data/y_train_v4.npy"
Y_TEST_OUT = "data/y_test_v4.npy"

ENCODER_OUT = Path("models") / "onehot_encoder_v4.pkl"


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

FEATURES = NUMERIC_COLS + CATEGORICAL_COLS
LABEL_COL = "label"


def _make_ohe() -> OneHotEncoder:
    try:
        return OneHotEncoder(handle_unknown="ignore", sparse_output=False)
    except TypeError:
        return OneHotEncoder(handle_unknown="ignore", sparse=False)


def main() -> None:
    train_df = pd.read_csv(TRAIN_CSV)
    test_df = pd.read_csv(TEST_CSV)

    missing = [c for c in FEATURES + [LABEL_COL] if c not in train_df.columns or c not in test_df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    X_train_df = train_df[FEATURES].copy()
    X_test_df = test_df[FEATURES].copy()

    # Missing values handling
    for col in CATEGORICAL_COLS:
        X_train_df[col] = X_train_df[col].fillna("UNKNOWN").astype(str)
        X_test_df[col] = X_test_df[col].fillna("UNKNOWN").astype(str)

    for col in NUMERIC_COLS:
        X_train_df[col] = pd.to_numeric(X_train_df[col], errors="coerce").fillna(0)
        X_test_df[col] = pd.to_numeric(X_test_df[col], errors="coerce").fillna(0)

    y_train = pd.to_numeric(train_df[LABEL_COL], errors="coerce").fillna(0).astype(int).clip(0, 1).to_numpy()
    y_test = pd.to_numeric(test_df[LABEL_COL], errors="coerce").fillna(0).astype(int).clip(0, 1).to_numpy()

    # Encoding: fit only on training categoricals
    ohe = _make_ohe()
    X_train_cat = ohe.fit_transform(X_train_df[CATEGORICAL_COLS])
    X_test_cat = ohe.transform(X_test_df[CATEGORICAL_COLS])

    X_train_num = X_train_df[NUMERIC_COLS].to_numpy(dtype=np.float32, copy=True)
    X_test_num = X_test_df[NUMERIC_COLS].to_numpy(dtype=np.float32, copy=True)

    X_train = np.hstack([X_train_num, X_train_cat]).astype(np.float32, copy=False)
    X_test = np.hstack([X_test_num, X_test_cat]).astype(np.float32, copy=False)

    # Save outputs
    np.save(X_TRAIN_OUT, X_train)
    np.save(X_TEST_OUT, X_test)
    np.save(Y_TRAIN_OUT, y_train)
    np.save(Y_TEST_OUT, y_test)

    ENCODER_OUT.parent.mkdir(parents=True, exist_ok=True)
    dump(ohe, ENCODER_OUT)

    # Print verification summary (no extra output)
    train_rows = int(X_train.shape[0])
    test_rows = int(X_test.shape[0])
    pos = int((y_train == 1).sum())
    neg = int((y_train == 0).sum())

    print(f"train rows: {train_rows}")
    print(f"test rows: {test_rows}")
    print(f"y_train positives: {pos}")
    print(f"y_train negatives: {neg}")
    print(f"X_train shape: {X_train.shape}")
    print(f"X_test shape: {X_test.shape}")
    print(f"final feature count: {X_train.shape[1]}")
    print(f"X_train NaNs: {int(np.isnan(X_train).sum())}")
    print(f"X_test NaNs: {int(np.isnan(X_test).sum())}")


if __name__ == "__main__":
    main()
