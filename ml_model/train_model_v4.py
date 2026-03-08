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


BASE_DIR = Path(__file__).resolve().parent

X_TRAIN_PATH = BASE_DIR / "data" / "X_train_v4.npy"
X_TEST_PATH = BASE_DIR / "data" / "X_test_v4.npy"
Y_TRAIN_PATH = BASE_DIR / "data" / "y_train_v4.npy"
Y_TEST_PATH = BASE_DIR / "data" / "y_test_v4.npy"

MODELS_DIR = BASE_DIR / "models"
LOGIT_OUT = MODELS_DIR / "logistic_model_v4.pkl"
XGB_OUT = MODELS_DIR / "xgboost_model_v4.pkl"


def _ensure_binary_labels(y: np.ndarray) -> None:
    uniq = set(np.unique(y).tolist())
    if not uniq.issubset({0, 1}):
        raise ValueError("Labels must be binary (0/1)")


def _print_results_block(name: str, y_true: np.ndarray, y_proba: np.ndarray) -> None:
    y_pred = (y_proba >= 0.5).astype(int)

    uniq = set(np.unique(y_true).tolist())
    if len(uniq) < 2:
        roc_line = "ROC-AUC: N/A (only one class present)"
    else:
        roc = roc_auc_score(y_true, y_proba)
        roc_line = f"ROC-AUC: {roc:.6f}"

    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_true, y_pred)

    print(f"{name} Results")
    print(roc_line)
    print(f"Precision: {precision:.6f}")
    print(f"Recall: {recall:.6f}")
    print(f"F1: {f1:.6f}")
    print("Confusion Matrix:")
    print(cm)
    print("")


def main() -> None:
    X_train = np.load(X_TRAIN_PATH)
    X_test = np.load(X_TEST_PATH)
    y_train = np.load(Y_TRAIN_PATH)
    y_test = np.load(Y_TEST_PATH)

    _ensure_binary_labels(y_train)
    _ensure_binary_labels(y_test)

    train_pos = int((y_train == 1).sum())
    train_neg = int((y_train == 0).sum())

    print(f"Training samples count: {X_train.shape[0]}")
    print(f"Test samples count: {X_test.shape[0]}")
    print(f"Number of features: {X_train.shape[1]}")
    print(f"Training positives: {train_pos}")
    print(f"Training negatives: {train_neg}")

    if train_pos == 0:
        raise ValueError("Training positives must be > 0")
    scale_pos_weight = train_neg / train_pos

    # Save models safely (no overwrite)
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    if LOGIT_OUT.exists():
        raise FileExistsError(f"Model file already exists: {LOGIT_OUT}")
    if XGB_OUT.exists():
        raise FileExistsError(f"Model file already exists: {XGB_OUT}")

    # Model 1 — Logistic Regression (Baseline)
    logit_model = LogisticRegression(
        max_iter=1000,
        class_weight="balanced",
        solver="lbfgs",
    )
    logit_model.fit(X_train, y_train)

    # Model 2 — XGBoost (Main Model)
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

    # Predictions (probability for class 1)
    logit_proba = logit_model.predict_proba(X_test)[:, 1]
    xgb_proba = xgb_model.predict_proba(X_test)[:, 1]

    # Evaluation
    _print_results_block("Logistic Regression", y_test, logit_proba)
    _print_results_block("XGBoost", y_test, xgb_proba)

    dump(logit_model, LOGIT_OUT)
    dump(xgb_model, XGB_OUT)


if __name__ == "__main__":
    main()
