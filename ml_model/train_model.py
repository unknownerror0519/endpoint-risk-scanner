from __future__ import annotations

from pathlib import Path

import numpy as np
from joblib import dump
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from xgboost import XGBClassifier


X_TRAIN_PATH = "data/X_train.npy"
X_TEST_PATH = "data/X_test.npy"
Y_TRAIN_PATH = "data/y_train.npy"
Y_TEST_PATH = "data/y_test.npy"

MODELS_DIR = Path("models")
LOGIT_OUT = MODELS_DIR / "logistic_model.pkl"
XGB_OUT = MODELS_DIR / "xgboost_model.pkl"


def _evaluate_model(name: str, y_true: np.ndarray, y_proba: np.ndarray) -> None:
    y_pred = (y_proba >= 0.5).astype(np.int64)

    roc_auc = roc_auc_score(y_true, y_proba)
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_true, y_pred)

    print(f"\n{name} Results")
    print(f"ROC-AUC: {roc_auc:.6f}")
    print(f"Precision: {precision:.6f}")
    print(f"Recall: {recall:.6f}")
    print(f"F1: {f1:.6f}")
    print("Confusion Matrix:")
    print(cm)


def main() -> None:
    X_train = np.load(X_TRAIN_PATH)
    X_test = np.load(X_TEST_PATH)
    y_train = np.load(Y_TRAIN_PATH)
    y_test = np.load(Y_TEST_PATH)

    print(f"Training samples count: {X_train.shape[0]}")
    print(f"Test samples count: {X_test.shape[0]}")
    print(f"Number of features: {X_train.shape[1]}")

    pos = int((y_train == 1).sum())
    neg = int((y_train == 0).sum())
    if pos == 0:
        raise ValueError("y_train has 0 positive samples; cannot compute scale_pos_weight")
    scale_pos_weight = neg / pos

    # Model #1 — Logistic Regression (baseline)
    logit_model = LogisticRegression(max_iter=1000, class_weight="balanced", n_jobs=-1)
    logit_model.fit(X_train, y_train)

    # Model #2 — XGBoost (main model)
    xgb_model = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale_pos_weight,
        eval_metric="logloss",
        n_jobs=-1,
        random_state=42,
    )
    xgb_model.fit(X_train, y_train)

    # Probability predictions for class 1
    logit_proba = logit_model.predict_proba(X_test)[:, 1]
    xgb_proba = xgb_model.predict_proba(X_test)[:, 1]

    # Evaluation
    _evaluate_model("Logistic Regression", y_test, logit_proba)
    _evaluate_model("XGBoost", y_test, xgb_proba)

    # Save models
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    dump(logit_model, LOGIT_OUT)
    dump(xgb_model, XGB_OUT)


if __name__ == "__main__":
    main()
