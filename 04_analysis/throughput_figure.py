"""
throughput_figure.py — Figura de impacto DoS: throughput por cliente desde traffic.db (§4b).

Produce la gráfica "de dos usuarios": la serie del ATACANTE sube durante la ventana de ataque
mientras la del CLIENTE NORMAL cae (el ESP32 saturado deja de atenderlo). Es la evidencia de
atenuación del throughput que pide el informe. Formato visual alineado con las figuras Kaggle
(fig_paper_scatter.png): Y log, ventanas de ataque sombreadas, colores azul/naranja/rojo.

NO toca el modelo ni el servicio: solo lee SQLite. Correr en la máquina con traffic.db:
    python 04_analysis/throughput_figure.py [--db ruta/traffic.db] [--win 5]

Métrica: por ventana de `--win` segundos y por src_ip,
    pkts/s   = Σ(in_pkts+out_pkts) del flujo repartidos uniformemente sobre su duración
    bytes/s  = idem con in_bytes+out_bytes
El reparto uniforme evita el sesgo de asignar todo el flujo a su ts_start (flujos largos).
Para el "downlink" del cliente normal (lo que el ESP32 logra responderle) usar out_bytes.

Consulta SQL base (equivalente simple, asignando el flujo a la ventana de su ts_start):
    SELECT CAST(ts_start/:win AS INT)*:win AS ventana, src_ip,
           SUM(in_pkts+out_pkts)/(:win*1.0)  AS pkts_s,
           SUM(out_bytes)*8/(:win*1.0)       AS bits_s_downlink
    FROM flows GROUP BY ventana, src_ip ORDER BY ventana;
"""
from __future__ import annotations
import argparse, sqlite3, sys
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.append(str(Path(__file__).resolve().parents[1]))
import config  # noqa: E402

AZUL, NARANJA, ROJO = "tab:blue", "tab:orange", "red"


def cargar(db: Path):
    conn = sqlite3.connect(db)
    flows = pd.read_sql("SELECT ts_start, ts_end, src_ip, in_pkts, out_pkts, in_bytes, out_bytes "
                        "FROM flows", conn)
    wins = pd.read_sql("SELECT family, ts_start, ts_end FROM attack_windows", conn)
    conn.close()
    return flows, wins


def series_por_cliente(flows: pd.DataFrame, win_s: float):
    """Reparte cada flujo uniformemente sobre [ts_start, ts_end] en ventanas de win_s."""
    t0 = flows.ts_start.min()
    filas = []
    for f in flows.itertuples(index=False):
        dur = max(f.ts_end - f.ts_start, 1e-3)
        pk, by = (f.in_pkts + f.out_pkts) / dur, (f.in_bytes + f.out_bytes) / dur
        by_down = f.out_bytes / dur                     # respuesta del ESP32 hacia el cliente
        w = np.floor(f.ts_start / win_s) * win_s
        while w < f.ts_end:
            solape = min(f.ts_end, w + win_s) - max(f.ts_start, w)
            if solape > 0:
                filas.append((w, f.src_ip, pk * solape / win_s, by * solape / win_s,
                              by_down * solape / win_s))
            w += win_s
    df = (pd.DataFrame(filas, columns=["ventana", "src_ip", "pkts_s", "bytes_s", "bytes_s_down"])
          .groupby(["ventana", "src_ip"]).sum().reset_index())
    df["t_rel"] = df.ventana - t0
    return df, t0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=str(config.DB_PATH))
    ap.add_argument("--win", type=float, default=5.0, help="ventana en segundos")
    ap.add_argument("--out", default="04_analysis/throughput_clientes.png")
    args = ap.parse_args()

    flows, wins = cargar(Path(args.db))
    df, t0 = series_por_cliente(flows, args.win)

    # top clientes por volumen (el atacante y el/los normales dominan)
    tops = df.groupby("src_ip").pkts_s.sum().sort_values(ascending=False).head(4).index

    fig, ax = plt.subplots(2, 1, figsize=(14, 8), sharex=True)
    colores = [NARANJA, AZUL, "tab:green", "tab:purple"]
    for i, ip in enumerate(tops):
        d = df[df.src_ip == ip]
        ax[0].plot(d.t_rel, d.pkts_s, label=f"{ip} (pkts/s)", color=colores[i % 4], lw=1.4)
        ax[1].plot(d.t_rel, d.bytes_s_down * 8, label=f"{ip} (bits/s downlink)",
                   color=colores[i % 4], lw=1.4)
    for a in ax:
        for w in wins.itertuples(index=False):        # ventanas de ataque sombreadas
            a.axvspan(w.ts_start - t0, w.ts_end - t0, alpha=0.12, color=ROJO)
        a.set_yscale("log"); a.legend(fontsize=8); a.grid(alpha=0.2)
    ax[0].set_ylabel("pkts/s (log)")
    ax[0].set_title("Throughput por cliente — el atacante sube; sombreado = ventana de ataque")
    ax[1].set_ylabel("bits/s hacia el cliente (log)")
    ax[1].set_title("Downlink por cliente — la ATENUACIÓN del cliente normal durante el ataque")
    ax[1].set_xlabel(f"tiempo desde el inicio de la captura (s), ventanas de {args.win:.0f}s")
    plt.tight_layout()
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(args.out, dpi=140, bbox_inches="tight")
    print(f"[throughput] figura -> {args.out}")
    print("[throughput] clientes:", list(tops))
    # Nota metodológica: esto mide carga OFRECIDA/atendida vista en la red. Para el impacto
    # de servicio directo (RTT y tasa de éxito del cliente normal), instrumentar
    # generate_normal.py para registrar rtt_ms y status por request (recomendación 4b-2).


if __name__ == "__main__":
    main()
