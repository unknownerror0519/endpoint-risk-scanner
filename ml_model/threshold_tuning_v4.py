from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
from joblib import load
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score


BASE_DIR = Path(__file__).resolve().parent

MODEL_PATH = BASE_DIR / "models" / "xgboost_model_v4.pkl"
X_TEST_PATH = BASE_DIR / "data" / "X_test_v4.npy"
Y_TEST_PATH = BASE_DIR / "data" / "y_test_v4.npy"

REPORTS_DIR = BASE_DIR / "reports"
REPORT_PATH = REPORTS_DIR / "threshold_report_v4.csv"


def _ensure_binary_labels(y: np.ndarray) -> None:
    uniq = set(np.unique(y).tolist())
    if not uniq.issubset({0, 1}):
        raise ValueError("Labels must be binary (0/1)")


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
    model = load(MODEL_PATH)
    X_test = np.load(X_TEST_PATH)
    y_test = np.load(Y_TEST_PATH)

    _ensure_binary_labels(y_test)

    y_proba = model.predict_proba(X_test)[:, 1]

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
    _print_best("Best threshold by F1-score", best_f1)

    _print_best("Best threshold with precision >= 0.10", _select_best_with_precision(report_df, 0.10))
    _print_best("Best threshold with precision >= 0.20", _select_best_with_precision(report_df, 0.20))
    _print_best("Best threshold with precision >= 0.30", _select_best_with_precision(report_df, 0.30))


if __name__ == "__main__":
    main()
