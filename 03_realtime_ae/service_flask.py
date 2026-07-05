"""
service_flask.py — Servicio HTTP que encapsula el AE (rol del ml-service del repo de referencia).

Endpoints (contrato en ARCHITECTURE §4):
  POST /predict   features de un flujo -> {anomaly, score, threshold, flow_id}
  GET  /stream    SSE: empuja cada evento al dashboard en vivo
  GET  /          sirve templates/dashboard.html
  GET  /health    {status, model_loaded}

Escribe cada veredicto en SQLite (tabla events) para el dashboard y el análisis post-hoc.

MiniMax: implementa los TODO. Carga los artifacts UNA vez al arrancar (no por request).
"""
from __future__ import annotations
import json, pickle, queue, sqlite3, sys, time
from pathlib import Path

import numpy as np
import torch
from flask import Flask, request, jsonify, Response, render_template

sys.path.append(str(Path(__file__).resolve().parents[1]))
import config  # noqa: E402
from ae_model import build_model, reconstruction_error  # noqa: E402

app = Flask(__name__)

# Estado global cargado al arrancar (NO por request)
MODEL = None
SCALER = None
TAU = None
SUBSCRIBERS: list[queue.Queue] = []   # colas SSE, una por cliente del dashboard


def load_artifacts():
    """Carga MODEL, SCALER, TAU desde config.*_PATH (una sola vez, al arrancar)."""
    global MODEL, SCALER, TAU
    with open(config.SCALER_PATH, "rb") as fh:
        SCALER = pickle.load(fh)
    with open(config.THRESHOLD_PATH) as fh:
        TAU = float(json.load(fh)["valor"])
    MODEL = build_model(len(config.FEATURE_COLS))
    MODEL.load_state_dict(torch.load(config.MODEL_PATH, map_location="cpu"))
    MODEL.eval()


def featurize(features: dict) -> np.ndarray:
    """dict -> vector escalado (1,d) en el orden de config.FEATURE_COLS."""
    row = []
    for c in config.FEATURE_COLS:
        v = float(features.get(c, 0.0) or 0.0)
        if c in config.LOG_FEATURES:
            v = float(np.log1p(max(v, 0.0)))
        row.append(v)
    x = np.array([row], dtype=np.float32)
    return SCALER.transform(x).astype(np.float32)


def write_event(ev: dict):
    """INSERT en tabla events (incluye src_ip y pkts_per_s; ver db_schema.sql auditado).
    TODO: sqlite3.connect(config.DB_PATH); INSERT; commit; close."""
    conn = sqlite3.connect(config.DB_PATH)
    try:
        conn.execute(
            "INSERT INTO events(ts, flow_id, src_ip, score, threshold, anomaly, attack_family, pkts_per_s) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (ev["ts"], ev.get("flow_id"), ev.get("src_ip"), ev["score"], ev["threshold"],
             ev["anomaly"], ev.get("attack_family"), ev.get("pkts_per_s")))
        conn.commit()
    finally:
        conn.close()


def publish(ev: dict):
    """Empuja el evento a todos los suscriptores SSE (no bloqueante)."""
    for q in list(SUBSCRIBERS):
        try:
            q.put_nowait(ev)
        except queue.Full:
            pass


@app.route("/predict", methods=["POST"])
def predict():
    """AUDITORÍA §4b (2026-07-05): el evento incluye src_ip y pkts_per_s (opcionales) para el
    panel de throughput por cliente del dashboard. capture_agent.post_predict debe enviarlos.
    TODO:
      - body = request.get_json(); feats = body["features"]
      - x = featurize(feats); score = float(reconstruction_error(MODEL, torch.tensor(x))[0])
      - anomaly = score > TAU
      - ev = {"ts": time.time(), "flow_id": body.get("flow_id"), "score": score,
              "threshold": TAU, "anomaly": int(anomaly),
              "attack_family": body.get("attack_family"),
              "src_ip": body.get("src_ip"),                       # <- auditoría C2/§4b
              "pkts_per_s": feats.get("pkts_per_s")}              # <- auditoría §4b
      - write_event(ev); publish(ev)
      - return jsonify({"anomaly": bool(anomaly), "score": score, "threshold": TAU,
                        "flow_id": ev["flow_id"]})
    """
    body = request.get_json(force=True)
    feats = body["features"]
    x = featurize(feats)
    score = float(reconstruction_error(MODEL, torch.from_numpy(x))[0])
    anomaly = score > TAU
    ev = {"ts": time.time(), "flow_id": body.get("flow_id"), "score": score,
          "threshold": TAU, "anomaly": int(anomaly),
          "attack_family": body.get("attack_family"),
          "src_ip": body.get("src_ip"),
          "pkts_per_s": feats.get("pkts_per_s")}
    write_event(ev); publish(ev)
    return jsonify({"anomaly": bool(anomaly), "score": score, "threshold": TAU,
                    "flow_id": ev["flow_id"]})


@app.route("/stream")
def stream():
    """SSE: cada cliente recibe eventos en tiempo real."""
    def gen():
        q: queue.Queue = queue.Queue(maxsize=100)
        SUBSCRIBERS.append(q)
        try:
            while True:
                ev = q.get()
                yield f"data: {json.dumps(ev)}\n\n"
        finally:
            SUBSCRIBERS.remove(q)
    return Response(gen(), mimetype="text/event-stream")


@app.route("/health")
def health():
    return jsonify({"status": "ok", "model_loaded": MODEL is not None})


@app.route("/")
def index():
    return render_template("dashboard.html", threshold=TAU)


if __name__ == "__main__":
    load_artifacts()
    print(f"[service] AE cargado. tau={TAU}. Escuchando en "
          f"http://{config.SERVICE_HOST}:{config.SERVICE_PORT}")
    # threaded=True para que SSE y /predict convivan.
    app.run(host=config.SERVICE_HOST, port=config.SERVICE_PORT, threaded=True)
