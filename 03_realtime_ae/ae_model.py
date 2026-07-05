"""
ae_model.py — Definición del Autoencoder (reutiliza la arquitectura del notebook AE del proyecto).

Lógica de modelo pura (sin E/S). La usan train_ae.py (entrenar) y service_flask.py (inferir).
Este es de los pocos archivos que va casi COMPLETO, para que MiniMax no se trabe en la parte
matemática. Solo hay que verificar que las dimensiones cuadren con config.FEATURE_COLS.
"""
from __future__ import annotations
import sys
from pathlib import Path

import torch
import torch.nn as nn
import torch.nn.functional as F

sys.path.append(str(Path(__file__).resolve().parents[1]))
import config  # noqa: E402


class AE(nn.Module):
    """Autoencoder denso simétrico. Entrada = len(config.FEATURE_COLS)."""

    def __init__(self, d_in: int, enc_hidden=None, dec_hidden=None, d_z: int | None = None):
        super().__init__()
        enc_hidden = enc_hidden or config.ENC_HIDDEN
        dec_hidden = dec_hidden or config.DEC_HIDDEN
        d_z = d_z or config.LATENT_DIM

        enc, prev = [], d_in
        for h in enc_hidden:
            enc += [nn.Linear(prev, h), nn.ReLU()]; prev = h
        enc += [nn.Linear(prev, d_z)]
        self.encoder = nn.Sequential(*enc)

        dec, prev = [], d_z
        for h in dec_hidden:
            dec += [nn.Linear(prev, h), nn.ReLU()]; prev = h
        dec += [nn.Linear(prev, d_in)]
        self.decoder = nn.Sequential(*dec)

    def forward(self, x):
        return self.decoder(self.encoder(x))


@torch.no_grad()
def reconstruction_error(model: AE, X: torch.Tensor) -> torch.Tensor:
    """Error de reconstrucción por muestra (MSE sobre features). Es el SCORE de anomalía."""
    model.eval()
    xhat = model(X)
    return F.mse_loss(xhat, X, reduction="none").mean(dim=1)


def build_model(d_in: int) -> AE:
    return AE(d_in)
