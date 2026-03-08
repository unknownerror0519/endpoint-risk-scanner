from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from joblib import load
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score


BASE_DIR = Path(__file__).resolve().parent

MODEL_PATH = BASE_DIR / "models" / "xgboost_model_v4_calibrated.pkl"
X_TEST_PATH = BASE_DIR / "data" / "X_test_v4.npy"
Y_TEST_PATH = BASE_DIR / "data" / "y_test_v4.npy"

REPORTS_DIR = BASE_DIR / "reports"
REPORT_PATH = REPORTS_DIR / "threshold_report_v4_calibrated.csv"


def _ensure_binary_y_test(y_test: np.ndarray) -> None:
    uniq = set(np.unique(y_test).tolist())
    if not uniq.issubset({0, 1}):
        raise ValueError("y_test must be binary (0/1)")


def _predict_proba_class1(model_obj: Any, X: np.ndarray) -> np.ndarray:
    # Option B: calibrated model object with predict_proba
    if hasattr(model_obj, "predict_proba"):
        proba = model_obj.predict_proba(X)
        return np.asarray(proba)[:, 1]

    # Option A: dict with base_model + isotonic_calibrator
    if isinstance(model_obj, dict) and "base_model" in model_obj and "isotonic_calibrator" in model_obj:
        base_model = model_obj["base_model"]
        calibrator = model_obj["isotonic_calibrator"]
        if not hasattr(base_model, "predict_proba"):
            raise ValueError("base_model does not implement predict_proba")
        if not hasattr(calibrator, "transform"):
            raise ValueError("isotonic_calibrator does not implement transform")
        raw = np.asarray(base_model.predict_proba(X))[:, 1]
        calibrated = calibrator.transform(raw)
        return np.asarray(calibrated)

    raise ValueError(
        "Unsupported calibrated model artifact: expected an object with predict_proba(X) or a dict with keys 'base_model' and 'isotonic_calibrator'"
    )


def _select_best_by_f1(df: pd.DataFrame) -> pd.Series:
    return df.sort_values(["f1", "threshold"], ascending=[False, True]).iloc[0]


def _select_best_with_precision(df: pd.DataFrame, min_precision: float) -> pd.Series | None:
    subset = df[df["precision"] >= min_precision]
    if subset.empty:
        return None
    return subset.sort_values(["f1", "threshold"], ascending=[False, True]).iloc[0]


def _print_best(label: str, row: pd.Series | None) -> None:
    print(label)
    if row is None:
        print("No threshold meets the constraint")
        print("")
        return

    print(f"threshold: {row['threshold']:.2f}")
    print(f"precision: {row['precision']:.6f}")
    print(f"recall: {row['recall']:.6f}")
    print(f"f1: {row['f1']:.6f}")
    print(f"tp: {int(row['tp'])}")
    print(f"fp: {int(row['fp'])}")
    print(f"fn: {int(row['fn'])}")
    print(f"tn: {int(row['tn'])}")
    print("")


def main() -> None:
    model_obj = load(MODEL_PATH)
    X_test = np.load(X_TEST_PATH)
    y_test = np.load(Y_TEST_PATH)

    _ensure_binary_y_test(y_test)

    y_proba = _predict_proba_class1(model_obj, X_test)

    thresholds = [round(x, 2) for x in np.arange(0.05, 0.951, 0.05)]

    rows: list[dict[str, float | int]] = []
    for thr in thresholds:
        y_pred = (y_proba >= thr).astype(int)

        precision = precision_score(y_test, y_pred, zero_division=0)
        recall = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)

        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = (int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1]))

        rows.append(
            {
                "threshold": float(thr),
                "precision": float(precision),
                "recall": float(recall),
                "f1": float(f1),
                "predicted_positives": int(y_pred.sum()),
                "tn": tn,
                "fp": fp,
                "fn": fn,
                "tp": tp,
            }
        )

    report_df = pd.DataFrame(
        rows,
        columns=[
            "threshold",
            "precision",
            "recall",
            "f1",
            "predicted_positives",
            "tn",
            "fp",
            "fn",
            "tp",
        ],
    ).sort_values("threshold", ascending=True)

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if REPORT_PATH.exists():
        raise FileExistsError(f"Report file already exists: {REPORT_PATH}")
    report_df.to_csv(REPORT_PATH, index=False)

    test_count = int(len(y_test))
    pos_count = int((y_test == 1).sum())

    print(f"Test sample count: {test_count}")
    print(f"Positive count in y_test: {pos_count}")
    print("Threshold table:")
    print(report_df.to_string(index=False))
    print("")

    best_f1 = _select_best_by_f1(report_df)
    best_p10 = _select_best_with_precision(report_df, 0.10)
    best_p20 = _select_best_with_precision(report_df, 0.20)
    best_p30 = _select_best_with_precision(report_df, 0.30)

    _print_best("Best threshold by F1-score", best_f1)
    _print_best("Best threshold with precision >= 0.10", best_p10)
    _print_best("Best threshold with precision >= 0.20", best_p20)
    _print_best("Best threshold with precision >= 0.30", best_p30)

    # Recommended production threshold logic:
    # - Start with best F1
    # - If a threshold with precision >= 0.20 exists and its recall is not drastically lower,
    #   prefer it. "Not drastically lower" is defined here as recall >= 90% of best-F1 recall.
    recommended = best_f1
    best_f1_recall = float(best_f1["recall"])

    if best_p20 is not None:
        p20_recall = float(best_p20["recall"])
        if best_f1_recall == 0.0 or p20_recall >= 0.9 * best_f1_recall:
            recommended = best_p20

    best_f1_thr_str = f"{float(best_f1['threshold']):.2f}"
    best_p20_thr_str = "N/A" if best_p20 is None else f"{float(best_p20['threshold']):.2f}"
    recommended_thr_str = f"{float(recommended['threshold']):.2f}"
    print(
        "Recommended production threshold: "
        f"{recommended_thr_str} (best-F1={best_f1_thr_str}, best-precision>=0.20={best_p20_thr_str})"
    )


if __name__ == "__main__":
    main()
