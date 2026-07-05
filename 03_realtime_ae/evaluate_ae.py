"""
evaluate_ae.py — Valida el AE sobre dataset_test.csv (benigno+ataque) con ground truth.

Reporta las métricas del proyecto: AUC-ROC (principal), matriz de confusión al umbral, recall,
F2, MCC, FPR, y DETECCIÓN POR FAMILIA de ataque. Es la evidencia de "aplicabilidad" del informe.

MiniMax: implementa los TODO. Usa el umbral guardado por train_ae (no recalibrar sobre el test).
"""
from __future__ import annotations
import json, pickle, sys
from pathlib import Path

import numpy as np
import torch

sys.path.append(str(Path(__file__).resolve().parents[1]))
import config  # noqa: E402
from ae_model import build_model, reconstruction_error  # noqa: E402


def load_artifacts():
    """Carga model, scaler, umbral desde artifacts/."""
    with open(config.SCALER_PATH, "rb") as fh:
        scaler = pickle.load(fh)
    with open(config.THRESHOLD_PATH) as fh:
        tau = float(json.load(fh)["valor"])
    model = build_model(len(config.FEATURE_COLS))
    model.load_state_dict(torch.load(config.MODEL_PATH, map_location="cpu"))
    model.eval()
    return model, scaler, tau


def load_test():
    """Carga dataset_test.csv. Devuelve (X_scaled, y, familias). Aplica log1p + scaler guardado."""
    import pandas as pd
    _, scaler, _ = load_artifacts()
    df = pd.read_csv(config.DATASET_TEST)
    X = df[config.FEATURE_COLS].astype(float).copy()
    for c in config.LOG_FEATURES:
        if c in config.FEATURE_COLS:
            X[c] = np.log1p(X[c].clip(lower=0))
    Xs = scaler.transform(X.values).astype(np.float32)
    return Xs, df["label"].astype(int).values, df["attack_family"].astype(str).values


def evaluate():
    """Calcula y muestra métricas + tabla por familia. Guarda evaluate_report.json.
    TODO:
      - err = reconstruction_error(model, torch.tensor(Xs)).numpy()
      - from sklearn.metrics import roc_auc_score, confusion_matrix, matthews_corrcoef, fbeta_score,
        precision_recall_fscore_support
      - auc = roc_auc_score(y, err)
      - y_pred = (err > tau).astype(int)
      - métricas globales + matriz de confusión + FPR
      - tabla por familia: para cada attack_family, tasa de detección (recall);
        para 'benign' esa tasa es la FPR.
      - volcar todo a evaluate_report.json y a stdout.
    """
    from sklearn.metrics import (roc_auc_score, confusion_matrix, matthews_corrcoef,
                                 fbeta_score, precision_recall_fscore_support)
    model, scaler, tau = load_artifacts()
    Xs, y, fam = load_test()
    err = reconstruction_error(model, torch.from_numpy(Xs)).numpy()
    y_pred = (err > tau).astype(int)
    auc = float(roc_auc_score(y, err)) if len(set(y)) > 1 else float("nan")
    tn, fp, fn, tp = confusion_matrix(y, y_pred, labels=[0, 1]).ravel()
    prec, rec, f1, _ = precision_recall_fscore_support(
        y, y_pred, average="binary", pos_label=1, zero_division=0)
    report = {
        "tau": tau, "auc_roc": auc,
        "tpr_global": float(rec), "precision": float(prec), "f1": float(f1),
        "f2": float(fbeta_score(y, y_pred, beta=2, average="binary", zero_division=0)),
        "mcc": float(matthews_corrcoef(y, y_pred)) if len(set(y)) > 1 else float("nan"),
        "fpr": float(fp / (fp + tn)) if (fp + tn) else float("nan"),
        "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "n_test": int(len(y)), "prevalencia_ataque": float((y == 1).mean()),
        "por_familia": {},
    }
    import numpy as _np
    for f_ in sorted(set(fam)):
        m = fam == f_
        tasa = float(y_pred[m].mean())          # recall; para benign = FPR
        report["por_familia"][f_] = {"n": int(m.sum()), "tasa_deteccion": round(tasa, 4)}
    with open(Path(config.ARTIFACTS_DIR).parent / "evaluate_report.json", "w") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    print(f"[eval] AUC-ROC={auc:.4f}  TPR={rec:.3f}  FPR={report['fpr']:.3f}  MCC={report['mcc']:.3f}")
    print(f"[eval] matriz: TN={tn} FP={fp} FN={fn} TP={tp}")
    for f_, d in report["por_familia"].items():
        etq = "FPR" if f_ == "benign" else "recall"
        print(f"[eval]   {f_:10s} n={d['n']:5d}  {etq}={d['tasa_deteccion']:.3f}")
    return report


if __name__ == "__main__":
    evaluate()
