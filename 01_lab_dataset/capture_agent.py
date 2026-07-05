"""
capture_agent.py — Sniff pasivo (Scapy) → PacketView → FlowAggregator → SQLite/CSV o /predict.

Dos modos:
  --mode collect  : captura y escribe flujos a SQLite (tabla flows). Para construir el dataset.
  --mode live     : captura y hace POST /predict al servicio Flask (capa 3). Para la demo en vivo.

Requiere permisos de captura (sudo o setcap). Filtra por config.ESP32_IP.

MiniMax: implementa los TODO. La lógica de agregación ya vive en flow_aggregator (no duplicar).
"""
from __future__ import annotations
import argparse, sqlite3, time, sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))
import config  # noqa: E402
from flow_aggregator import FlowAggregator, PacketView  # noqa: E402


def scapy_to_view(pkt) -> PacketView | None:
    """Convierte un paquete scapy en PacketView. Devuelve None si no es IP/TCP-UDP-ICMP."""
    from scapy.all import IP, TCP, UDP, ICMP
    if IP not in pkt:
        return None
    ip = pkt[IP]
    if TCP in pkt:
        l4 = pkt[TCP]; proto = 6; sport = int(l4.sport); dport = int(l4.dport)
        flags = int(l4.flags)
    elif UDP in pkt:
        l4 = pkt[UDP]; proto = 17; sport = int(l4.sport); dport = int(l4.dport); flags = 0
    elif ICMP in pkt:
        proto = 1; sport = 0; dport = 0; flags = 0
    else:
        return None
    return PacketView(ts=float(pkt.time), src_ip=ip.src, dst_ip=ip.dst,
                      src_port=sport, dst_port=dport, protocol=proto,
                      length=int(len(pkt)), tcp_flags=flags)


def write_flows_sqlite(conn: sqlite3.Connection, flows: list[dict]) -> None:
    """INSERT OR REPLACE de una lista de flujos en la tabla flows."""
    if not flows:
        return
    cols = ["flow_id", "ts_start", "ts_end", "src_ip", "dst_ip", "src_port", "dst_port",
            "protocol", "duration_ms", "in_bytes", "out_bytes", "in_pkts", "out_pkts",
            "tcp_flags", "pkts_per_s", "bytes_per_pkt", "iat_mean_ms"]
    ph = ",".join("?" * len(cols))
    sql = f"INSERT OR REPLACE INTO flows ({','.join(cols)}) VALUES ({ph})"
    conn.executemany(sql, [[f.get(c) for c in cols] for f in flows])


def post_predict(flow: dict) -> None:
    """POST del vector de features al servicio Flask (modo live).
    AUDITORÍA §4b (2026-07-05): el payload incluye src_ip y flow_id para que el dashboard
    grafique throughput por cliente (atacante vs usuario normal).
    TODO:
      - import requests
      - payload = {"features": {c: flow[c] for c in config.FEATURE_COLS},
                   "src_ip": flow.get("src_ip"), "flow_id": flow.get("flow_id")}
      - requests.post(f"http://{config.SERVICE_HOST}:{config.SERVICE_PORT}/predict", json=payload, timeout=1)
      - manejar excepción de conexión sin abortar la captura.
    """
    import requests
    payload = {"features": {c: flow[c] for c in config.FEATURE_COLS},
               "src_ip": flow.get("src_ip"), "flow_id": flow.get("flow_id")}
    try:
        requests.post(f"http://{config.SERVICE_HOST}:{config.SERVICE_PORT}/predict",
                      json=payload, timeout=1)
    except requests.exceptions.RequestException as e:
        print(f"[capture][live] POST falló (¿servicio arriba?): {e}")


def run(mode: str, duration_s: float | None):
    from scapy.all import sniff  # import local: solo se necesita en la máquina de captura
    agg = FlowAggregator()
    conn = sqlite3.connect(config.DB_PATH) if mode == "collect" else None

    def handle(pkt):
        view = scapy_to_view(pkt)
        if view is None:
            return
        agg.add_packet(view)
        expired = agg.pop_expired(now=time.time())
        if expired:
            if mode == "collect":
                write_flows_sqlite(conn, expired); conn.commit()
            else:
                for f in expired:
                    post_predict(f)

    bpf = f"host {config.ESP32_IP}"   # solo tráfico del nodo víctima
    print(f"[capture] modo={mode} iface={config.CAPTURE_IFACE} filtro='{bpf}' dur={duration_s}")
    sniff(iface=config.CAPTURE_IFACE, filter=bpf, prn=handle, store=False, timeout=duration_s)

    # al terminar, cerrar flujos pendientes
    remaining = agg.flush_all(now=time.time())
    if mode == "collect" and remaining:
        write_flows_sqlite(conn, remaining); conn.commit()
    if conn:
        conn.close()
    print(f"[capture] fin. flujos pendientes cerrados: {len(remaining)}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["collect", "live"], required=True)
    ap.add_argument("--duration", type=float, default=None, help="segundos (None=infinito)")
    args = ap.parse_args()
    run(args.mode, args.duration)
