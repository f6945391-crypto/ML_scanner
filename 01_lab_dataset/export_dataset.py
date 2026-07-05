"""
export_dataset.py — Exporta desde SQLite dos CSV: normal (entrenar AE) y test (validar).

  dataset_normal.csv : SOLO flujos label=0 de la ventana benigna → entrena el AE.
  dataset_test.csv   : benigno + ataque (con label/attack_family) → valida el AE.

Regla anti-fuga: el AE NUNCA ve ataques en entrenamiento. Por eso el split es por ETIQUETA,
no aleatorio: todo lo benigno de la fase de recolección normal va a normal; la fase con ataques
(benigno+ataque) va a test.

MiniMax: implementa los TODO. Reporta % de duplicados (ver informe crítico: medir, no ocultar).
"""
from __future__ import annotations
import sqlite3, sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))
import config  # noqa: E402

EXPORT_COLS = config.META_COLS[:2] + config.FEATURE_COLS + ["iat_mean_ms"] + config.META_COLS[2:]
# = flow_id, ts_start, <11 features>, iat_mean_ms, label, attack_family


def export(conn: sqlite3.Connection) -> dict:
    """Escribe los dos CSV. Devuelve un resumen (filas, duplicados, prevalencia).
    TODO:
      - import pandas as pd
      - df = pd.read_sql("SELECT * FROM flows", conn)
      - dup_pct = df.duplicated(subset=config.FEATURE_COLS).mean()*100  (reportar)
      - normal = df[df.label==0][EXPORT_COLS]  -> dataset_normal.csv
      - test   = df[EXPORT_COLS]               -> dataset_test.csv   (todo, con etiquetas)
        (o, si la recolección normal y la de ataque están en corridas separadas por tiempo,
         separar por rango temporal; documentar la decisión.)
      - devolver {normal_rows, test_rows, dup_pct, prevalencia_ataque_en_test}
    """
    import pandas as pd
    df = pd.read_sql("SELECT * FROM flows", conn)
    if df.empty:
        raise SystemExit("[export] tabla flows vacía: primero captura y etiqueta.")
    dup_pct = df.duplicated(subset=config.FEATURE_COLS).mean() * 100.0
    normal = df[df.label == 0][EXPORT_COLS]
    test = df[EXPORT_COLS]                       # todo, con etiquetas (benigno+ataque)
    normal.to_csv(config.DATASET_NORMAL, index=False)
    test.to_csv(config.DATASET_TEST, index=False)
    prev = float((test["label"] == 1).mean()) if len(test) else 0.0
    return {"normal_rows": int(len(normal)), "test_rows": int(len(test)),
            "dup_pct": round(float(dup_pct), 2), "prevalencia_ataque_en_test": round(prev, 4)}


if __name__ == "__main__":
    conn = sqlite3.connect(config.DB_PATH)
    summary = export(conn)
    conn.close()
    print("[export] resumen:", summary)
    print(f"[export] normal -> {config.DATASET_NORMAL}")
    print(f"[export] test   -> {config.DATASET_TEST}")
