"""
train_ae.py — Entrena el AE con dataset_normal.csv y serializa los artifacts.

Anti-fuga: entrena SOLO con tráfico normal; el StandardScaler se ajusta SOLO con normal.
Fija el umbral tau sobre el error de reconstrucción de una partición de validación benigna.

Salidas: artifacts/{modelo.pt, scaler.pkl, umbral.json, meta.json}  (rutas en config).

MiniMax: implementa los TODO. La arquitectura y el score ya están en ae_model.py (no reimplementar).
"""
from __future__ import annotations
import json, pickle, sys
from pathlib import Path

import numpy as np
import torch
from torch.utils.data import DataLoader, TensorDataset

sys.path.append(str(Path(__file__).resolve().parents[1]))
import config  # noqa: E402
from ae_model import build_model, reconstruction_error  # noqa: E402


def load_normal():
    """Carga dataset_normal.csv, aplica log1p a config.LOG_FEATURES, devuelve X (np.float32).
    TODO:
      - import pandas as pd; df = pd.read_csv(config.DATASET_NORMAL)
      - X = df[config.FEATURE_COLS].astype(float)
      - for c in LOG_FEATURES if c in FEATURE_COLS: X[c] = np.log1p(clip(X[c],0))
      - return X.values.astype(np.float32)
    """
    import pandas as pd
    df = pd.read_csv(config.DATASET_NORMAL)
    X = df[config.FEATURE_COLS].astype(float).copy()
    for c in config.LOG_FEATURES:
        if c in config.FEATURE_COLS:
            X[c] = np.log1p(X[c].clip(lower=0))
    return X.values.astype(np.float32)


def fit_scaler(X):
    """Ajusta StandardScaler SOLO con normal. Devuelve (scaler, X_scaled)."""
    from sklearn.preprocessing import StandardScaler
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X).astype(np.float32)
    return scaler, Xs


def train(X_scaled) -> tuple:
    """Entrena el AE (split train/val benigno). Devuelve (model, err_val_ben np.array).
    TODO:
      - torch.manual_seed(config.SEED); np.random.seed(config.SEED)
      - split 90/10 (train/val) del normal
      - model = build_model(X.shape[1]); Adam(lr=config.LR)
      - loop EPOCHS con MSE(sum sobre features).mean(); early stopping por val MSE (PATIENCE)
      - devolver model y el vector de errores de reconstrucción sobre val benigno (para el umbral)
    """
    import torch.nn.functional as F
    from sklearn.model_selection import train_test_split
    torch.manual_seed(config.SEED); np.random.seed(config.SEED)
    X_tr, X_val = train_test_split(X_scaled, test_size=0.10, random_state=config.SEED)
    tr = DataLoader(TensorDataset(torch.from_numpy(X_tr)), batch_size=config.BATCH_SIZE, shuffle=True)
    va = DataLoader(TensorDataset(torch.from_numpy(X_val)), batch_size=config.BATCH_SIZE, shuffle=False)
    model = build_model(X_scaled.shape[1])
    opt = torch.optim.Adam(model.parameters(), lr=config.LR)
    best_val, best_state, pctr = float("inf"), None, 0
    for ep in range(config.EPOCHS):
        model.train()
        for (xb,) in tr:
            opt.zero_grad()
            loss = F.mse_loss(model(xb), xb, reduction="none").sum(dim=1).mean()
            loss.backward(); opt.step()
        model.eval(); vl = vn = 0.0
        with torch.no_grad():
            for (xb,) in va:
                vl += F.mse_loss(model(xb), xb, reduction="none").sum(dim=1).mean().item() * len(xb)
                vn += len(xb)
        vl /= max(vn, 1)
        if vl < best_val - 1e-4:
            best_val, pctr = vl, 0
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
        else:
            pctr += 1
            if pctr >= config.PATIENCE:
                print(f"[train] early stop @ ep {ep+1} (mejor val MSE {best_val:.4f})"); break
    if best_state is not None:
        model.load_state_dict(best_state)
    err_val = reconstruction_error(model, torch.from_numpy(X_val)).numpy()
    return model, err_val


def pick_threshold(err_val_ben: np.ndarray) -> dict:
    """Fija tau según config.THRESHOLD_METHOD sobre el error del val benigno.
    TODO:
      - "P95"/"P99" -> percentil; "mu+ksigma" -> mean + k*std
      - devolver {"metodo":..., "valor": float(tau), "features": config.FEATURE_COLS}
    """
    m = config.THRESHOLD_METHOD
    if m.startswith("P"):
        tau = float(np.percentile(err_val_ben, float(m[1:])))
    elif m.startswith("mu+") and m.endswith("sigma"):
        k = float(m[3:-5])
        tau = float(np.mean(err_val_ben) + k * np.std(err_val_ben))
    else:
        raise ValueError(f"THRESHOLD_METHOD desconocido: {m}")
    return {"metodo": m, "valor": tau, "features": config.FEATURE_COLS,
            "n_val_ben": int(len(err_val_ben))}


def main():
    config.ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    X = load_normal()
    scaler, Xs = fit_scaler(X)
    model, err_val = train(Xs)
    thr = pick_threshold(err_val)

    torch.save(model.state_dict(), config.MODEL_PATH)
    with open(config.SCALER_PATH, "wb") as f:
        pickle.dump(scaler, f)
    with open(config.THRESHOLD_PATH, "w") as f:
        json.dump(thr, f, indent=2)
    with open(config.META_PATH, "w") as f:
        json.dump({"latent_dim": config.LATENT_DIM, "epochs": config.EPOCHS,
                   "train_rows": int(len(X)), "seed": config.SEED,
                   "threshold": thr}, f, indent=2)
    print(f"[train] artifacts en {config.ARTIFACTS_DIR}")
    print(f"[train] umbral: {thr}")


if __name__ == "__main__":
    main()
