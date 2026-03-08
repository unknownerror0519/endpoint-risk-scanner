from __future__ import annotations

from pathlib import Path

import numpy as np
from joblib import dump, load
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import brier_score_loss, log_loss, roc_auc_score
from sklearn.model_selection import PredefinedSplit, train_test_split
from xgboost import XGBClassifier


BASE_DIR = Path(__file__).resolve().parent

MODEL_IN = BASE_DIR / "models" / "xgboost_model_v4.pkl"
X_TRAIN_PATH = BASE_DIR / "data" / "X_train_v4.npy"
X_TEST_PATH = BASE_DIR / "data" / "X_test_v4.npy"
Y_TRAIN_PATH = BASE_DIR / "data" / "y_train_v4.npy"
Y_TEST_PATH = BASE_DIR / "data" / "y_test_v4.npy"

MODEL_OUT = BASE_DIR / "models" / "xgboost_model_v4_calibrated.pkl"


def _ensure_binary_labels(y: np.ndarray) -> None:
    uniq = set(np.unique(y).tolist())
    if not uniq.issubset({0, 1}):
        raise ValueError("Labels must be binary (0/1)")


def _safe_roc_auc(y_true: np.ndarray, y_proba: np.ndarray) -> str:
    uniq = set(np.unique(y_true).tolist())
    if len(uniq) < 2:
        return "ROC-AUC: N/A (only one class present)"
    return f"ROC-AUC: {roc_auc_score(y_true, y_proba):.6f}"


def _eval_metrics(y_true: np.ndarray, y_proba: np.ndarray) -> tuple[str, float, float]:
    roc_line = _safe_roc_auc(y_true, y_proba)
    brier = float(brier_score_loss(y_true, y_proba))
    ll = float(log_loss(y_true, y_proba, labels=[0, 1]))
    return roc_line, brier, ll


def main() -> None:
    if MODEL_OUT.exists():
        raise FileExistsError(f"Model file already exists: {MODEL_OUT}")

    _ = load(MODEL_IN)

    X_train = np.load(X_TRAIN_PATH)
    X_test = np.load(X_TEST_PATH)
    y_train = np.load(Y_TRAIN_PATH)
    y_test = np.load(Y_TEST_PATH)

    _ensure_binary_labels(y_train)
    _ensure_binary_labels(y_test)

    # Calibration split from training data only
    X_train_base, X_calib, y_train_base, y_calib = train_test_split(
        X_train,
        y_train,
        test_size=0.2,
        stratify=y_train,
        random_state=42,
    )

    base_pos = int((y_train_base == 1).sum())
    base_neg = int((y_train_base == 0).sum())
    if base_pos == 0:
        raise ValueError("Training positives must be > 0")
    scale_pos_weight = base_neg / base_pos

    # Retrain a fresh base XGBoost model on X_train_base
    base_model = XGBClassifier(
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
    base_model.fit(X_train_base, y_train_base)

    # Calibrate probabilities using isotonic regression on held-out calibration set
    try:
        calibrated_model = CalibratedClassifierCV(
            base_model,
            method="isotonic",
            cv="prefit",
        )
        calibrated_model.fit(X_calib, y_calib)
    except Exception:
        # Newer scikit-learn versions removed cv="prefit".
        # Use a single predefined split: train on X_train_base and calibrate on X_calib.
        X_all = np.vstack([X_train_base, X_calib])
        y_all = np.concatenate([y_train_base, y_calib])
        test_fold = np.concatenate(
            [
                np.full(shape=(X_train_base.shape[0],), fill_value=-1, dtype=int),
                np.zeros(shape=(X_calib.shape[0],), dtype=int),
            ]
        )
        split = PredefinedSplit(test_fold)

        base_estimator_for_calib = XGBClassifier(
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
        calibrated_model = CalibratedClassifierCV(
            base_estimator_for_calib,
            method="isotonic",
            cv=split,
        )
        calibrated_model.fit(X_all, y_all)

    # Evaluate on untouched test set
    base_proba = base_model.predict_proba(X_test)[:, 1]
    calib_proba = calibrated_model.predict_proba(X_test)[:, 1]

    base_roc, base_brier, base_ll = _eval_metrics(y_test, base_proba)
    calib_roc, calib_brier, calib_ll = _eval_metrics(y_test, calib_proba)

    print(f"Training base samples count: {X_train_base.shape[0]}")
    print(f"Calibration samples count: {X_calib.shape[0]}")
    print(f"Test samples count: {X_test.shape[0]}")
    print("")

    print("Uncalibrated XGBoost v4")
    print(base_roc)
    print(f"Brier Score: {base_brier:.6f}")
    print(f"Log Loss: {base_ll:.6f}")
    print("")

    print("Calibrated XGBoost v4")
    print(calib_roc)
    print(f"Brier Score: {calib_brier:.6f}")
    print(f"Log Loss: {calib_ll:.6f}")
    print("")

    print(
        "Calibration improvement:\n"
        f"Brier delta = {base_brier - calib_brier:.6f}\n"
        f"LogLoss delta = {base_ll - calib_ll:.6f}"
    )

    # Save calibrated model (no overwrite)
    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    dump(calibrated_model, MODEL_OUT)


if __name__ == "__main__":
    main()
