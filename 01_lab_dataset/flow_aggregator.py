"""
flow_aggregator.py — Convierte paquetes en FLUJOS (5-tupla + timeout), estilo NetFlow.

Núcleo del contrato de datos: produce exactamente las columnas de config.FEATURE_COLS + metadatos.
Este archivo es lógica pura (sin captura ni red), así se puede TESTEAR con paquetes sintéticos
sin necesitar scapy ni el ESP32. capture_agent.py lo alimenta en vivo; test_flow_aggregator.py
lo valida offline.

MiniMax: implementa SOLO los TODO. No cambies las firmas ni el orden de columnas.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import hashlib
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))
import config  # noqa: E402


@dataclass
class PacketView:
    """Vista mínima y agnóstica de un paquete (lo que capture_agent extrae de scapy)."""
    ts: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int      # 6/17/1
    length: int        # bytes del paquete
    tcp_flags: int     # 0 si no-TCP


@dataclass
class FlowState:
    """Acumulador de un flujo abierto. 'forward' = del primer emisor visto."""
    flow_id: str
    ts_start: float
    ts_end: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    in_bytes: int = 0
    out_bytes: int = 0
    in_pkts: int = 0
    out_pkts: int = 0
    tcp_flags: int = 0
    _iats: list = field(default_factory=list)   # inter-arrival times (ms) para iat_mean
    _last_ts: float = 0.0


def flow_key(p: PacketView) -> str:
    """Clave canónica de flujo: 5-tupla NORMALIZADA (mismo id en ambos sentidos).
    TODO: ordenar (ip,port) de src/dst para que forward y backward compartan clave.
    Devolver hash corto estable.
    """
    a = (p.src_ip, p.src_port)
    b = (p.dst_ip, p.dst_port)
    lo, hi = sorted([a, b])
    raw = f"{lo}-{hi}-{p.protocol}"
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


class FlowAggregator:
    """Mantiene flujos abiertos, los cierra por timeout y emite dicts con el esquema del contrato."""

    def __init__(self, timeout_s: float = config.FLOW_TIMEOUT_S):
        self.timeout_s = timeout_s
        self.open: dict[str, FlowState] = {}

    def add_packet(self, p: PacketView) -> None:
        """Añade un paquete al flujo correspondiente (crea el flujo si no existe).
        Convención: 'forward' (out_*) = sentido del PRIMER emisor visto del flujo.
        """
        key = flow_key(p)
        fs = self.open.get(key)
        if fs is None:
            fs = FlowState(flow_id=hashlib.sha1(f"{key}-{p.ts}".encode()).hexdigest()[:16],
                           ts_start=p.ts, ts_end=p.ts,
                           src_ip=p.src_ip, dst_ip=p.dst_ip,
                           src_port=p.src_port, dst_port=p.dst_port, protocol=p.protocol)
            self.open[key] = fs
        # sentido respecto al primer emisor
        if (p.src_ip, p.src_port) == (fs.src_ip, fs.src_port):
            fs.out_bytes += p.length; fs.out_pkts += 1
        else:
            fs.in_bytes += p.length; fs.in_pkts += 1
        fs.tcp_flags |= int(p.tcp_flags)
        if fs._last_ts > 0:
            fs._iats.append((p.ts - fs._last_ts) * 1000.0)
        fs._last_ts = p.ts
        fs.ts_end = max(fs.ts_end, p.ts)

    def pop_expired(self, now: float) -> list[dict]:
        """Cierra y devuelve como dicts los flujos inactivos (now - ts_end > timeout)."""
        vencidos = [k for k, fs in self.open.items() if now - fs.ts_end > self.timeout_s]
        out = []
        for k in vencidos:
            out.append(self._finalize(self.open.pop(k)))
        return out

    def flush_all(self, now: float) -> list[dict]:
        """Cierra TODOS los flujos abiertos (fin de captura). Devuelve lista de dicts."""
        out = [self._finalize(fs) for fs in self.open.values()]
        self.open.clear()
        return out

    def _finalize(self, fs: FlowState) -> dict:
        """Calcula features derivadas y devuelve el dict con TODAS las columnas del contrato.
        TODO:
          - duration_ms = (ts_end - ts_start)*1000
          - total_pkts = in_pkts+out_pkts ; total_bytes = in_bytes+out_bytes
          - pkts_per_s = total_pkts / max(duration_s, 0.05)   # piso 0.05 s (auditoría A6:
            un epsilon minúsculo hace explotar la feature en flujos de 1 paquete)
          - bytes_per_pkt = total_bytes / max(total_pkts,1)
          - iat_mean_ms = mean(_iats) si hay, si no 0
          - Devolver dict con: flow_id, ts_start, ts_end, src_ip, dst_ip, src_port, dst_port,
            protocol, duration_ms, in_bytes, out_bytes, in_pkts, out_pkts, tcp_flags,
            pkts_per_s, bytes_per_pkt, iat_mean_ms   (label/attack_family los pone label_flows)
        """
        duration_s = max(fs.ts_end - fs.ts_start, 0.05)   # piso 0.05 s (auditoría A6)
        total_pkts = fs.in_pkts + fs.out_pkts
        total_bytes = fs.in_bytes + fs.out_bytes
        iat_mean_ms = (sum(fs._iats) / len(fs._iats)) if fs._iats else 0.0
        return {
            "flow_id": fs.flow_id, "ts_start": fs.ts_start, "ts_end": fs.ts_end,
            "src_ip": fs.src_ip, "dst_ip": fs.dst_ip,
            "src_port": fs.src_port, "dst_port": fs.dst_port, "protocol": fs.protocol,
            "duration_ms": (fs.ts_end - fs.ts_start) * 1000.0,
            "in_bytes": fs.in_bytes, "out_bytes": fs.out_bytes,
            "in_pkts": fs.in_pkts, "out_pkts": fs.out_pkts, "tcp_flags": fs.tcp_flags,
            "pkts_per_s": total_pkts / duration_s,
            "bytes_per_pkt": total_bytes / max(total_pkts, 1),
            "iat_mean_ms": iat_mean_ms,
        }


# --- Autotest mínimo (corre sin scapy): valida que un flujo TCP simple se agrega bien ---------
if __name__ == "__main__":
    agg = FlowAggregator(timeout_s=1.0)
    pkts = [
        PacketView(0.00, "10.0.0.1", "10.0.0.2", 44000, 80, 6, 60, 0x02),  # SYN forward
        PacketView(0.01, "10.0.0.2", "10.0.0.1", 80, 44000, 6, 60, 0x12),  # SYN-ACK back
        PacketView(0.02, "10.0.0.1", "10.0.0.2", 44000, 80, 6, 500, 0x18), # PSH-ACK forward
    ]
    for p in pkts:
        agg.add_packet(p)
    flows = agg.flush_all(now=10.0)
    assert len(flows) == 1, f"esperaba 1 flujo, salieron {len(flows)}"
    f = flows[0]
    for col in config.FEATURE_COLS:
        assert col in f, f"falta feature {col}"
    print("[OK] flow_aggregator: flujo agregado con todas las features:", f)
