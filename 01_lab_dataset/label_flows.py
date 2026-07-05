"""
label_flows.py — Etiqueta los flujos cruzando su timestamp con las ventanas de ataque.

Ground truth por construcción: un flujo cae en 'ataque' si su [ts_start, ts_end] solapa una
ventana de attack_windows; hereda la familia. Si no solapa ninguna, es 'benign'.

MiniMax: implementa el TODO (una sola pasada SQL o en Python). Idempotente: re-ejecutable.
"""
from __future__ import annotations
import sqlite3, sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))
import config  # noqa: E402


def label(conn: sqlite3.Connection) -> dict:
    """Asigna label/attack_family a cada fila de flows. Devuelve conteo por familia.
    TODO:
      - Cargar attack_windows (family, ts_start, ts_end).
      - Para cada flow, si [flow.ts_start, flow.ts_end] solapa alguna ventana -> label=1,
        attack_family = family de esa ventana; si no -> label=0, attack_family='benign'.
        (Solape: flow.ts_start <= w.ts_end AND flow.ts_end >= w.ts_start)
      - UPDATE flows SET label=?, attack_family=? WHERE flow_id=?
      - Devolver dict {familia: conteo}.
    """
    wins = conn.execute("SELECT family, ts_start, ts_end FROM attack_windows").fetchall()
    flows = conn.execute("SELECT flow_id, ts_start, ts_end FROM flows").fetchall()
    counts: dict = {}
    for flow_id, f_start, f_end in flows:
        fam = "benign"
        for w_family, w_start, w_end in wins:
            if f_start <= w_end and f_end >= w_start:   # solape temporal
                fam = w_family
                break
        lbl = 0 if fam == "benign" else 1
        conn.execute("UPDATE flows SET label=?, attack_family=? WHERE flow_id=?",
                     (lbl, fam, flow_id))
        counts[fam] = counts.get(fam, 0) + 1
    return counts


if __name__ == "__main__":
    conn = sqlite3.connect(config.DB_PATH)
    counts = label(conn)
    conn.commit(); conn.close()
    print("[label] flujos por familia:", counts)
    total = sum(counts.values()) if counts else 0
    print(f"[label] total={total}  ataque={total - counts.get('benign', 0) if counts else 0}")
