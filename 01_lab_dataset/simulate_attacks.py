"""
simulate_attacks.py — Lanza ataques CONTROLADOS contra el ESP32 y REGISTRA la ventana temporal.

Cada ataque escribe una fila en attack_windows (ts_start, ts_end, family, tool_cmd) que luego
label_flows.py usa como ground truth. Alcance fijado: synflood, httpflood, portscan (volumétricos,
fáciles, típicos de IoT). Slowloris/bruteforce quedan FUERA (baja señal).

ADVERTENCIA: solo contra tu propio ESP32 en red aislada de laboratorio. Intensidad limitada para
no reiniciar el nodo (ver ARCHITECTURE §7). Requiere: nmap, hping3, apache2-utils (ab); hping3 sudo.

MiniMax: implementa los TODO. Mantén intensidades MODERADAS (parámetros marcados abajo).
"""
from __future__ import annotations
import argparse, subprocess, sqlite3, time, sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))
import config  # noqa: E402

TARGET = config.ESP32_IP

# Comandos de ataque. Intensidad MODERADA a propósito (no tumbar el nodo antes de capturar).
ATTACKS = {
    # SYN flood: -i u2000 = 1 paquete cada 2ms (~500 pps), NO --flood (evita reinicio).
    "synflood":  ["sudo", "hping3", "-S", "-p", "80", "-i", "u2000", "-c", "3000", TARGET],
    # HTTP GET flood moderado: 20000 peticiones, 50 concurrentes.
    "httpflood": ["ab", "-n", "20000", "-c", "50", f"http://{TARGET}/info"],
    # Port scan TCP connect (no requiere root).
    "portscan":  ["nmap", "-sT", "-p", "1-1024", TARGET],
}

DURATION_HINT_S = {"synflood": 15, "httpflood": 30, "portscan": 25}  # solo informativo


def record_window(conn, family: str, ts_start: float, ts_end: float, cmd: str) -> None:
    """INSERT en attack_windows (ground truth para label_flows)."""
    conn.execute(
        "INSERT INTO attack_windows(family, ts_start, ts_end, target_ip, tool_cmd) "
        "VALUES (?,?,?,?,?)", (family, ts_start, ts_end, TARGET, cmd))


def launch(family: str) -> None:
    """Ejecuta un ataque y registra su ventana [ts_start, ts_end].
    TODO:
      - conn = sqlite3.connect(config.DB_PATH)
      - ts_start = time.time()
      - subprocess.run(ATTACKS[family], ...) capturando salida; tolerar returncode!=0
      - ts_end = time.time()
      - record_window(conn, family, ts_start, ts_end, " ".join(ATTACKS[family])); commit; close
      - imprimir resumen (family, duración real)
    """
    conn = sqlite3.connect(config.DB_PATH)
    cmd = ATTACKS[family]
    ts_start = time.time()
    try:
        subprocess.run(cmd, timeout=180, check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        print(f"[attack] {family}: timeout (se detuvo tras 180 s)")
    except OSError as e:
        print(f"[attack] {family}: no se pudo lanzar ({e}); ¿instalado hping3/nmap/ab?")
    ts_end = time.time()
    record_window(conn, family, ts_start, ts_end, " ".join(cmd))
    conn.commit(); conn.close()
    print(f"[attack] {family}: {ts_end - ts_start:.1f} s  ventana registrada")


def run_all(gap_s: float = 20.0) -> None:
    """Lanza los tres ataques en secuencia con un hueco de tráfico entre ellos.
    IMPORTANTE: dejar 'gap_s' de silencio entre ataques para separar ventanas y dar
    margen a que el ESP32 se recupere. Antes/después conviene tener tráfico NORMAL corriendo.
    """
    for fam in ["portscan", "httpflood", "synflood"]:   # de menos a más agresivo
        print(f"\n=== Lanzando {fam} (~{DURATION_HINT_S[fam]}s) ===")
        launch(fam)
        print(f"--- pausa {gap_s}s ---")
        time.sleep(gap_s)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack", choices=list(ATTACKS) + ["all"], default="all")
    ap.add_argument("--gap", type=float, default=20.0)
    args = ap.parse_args()
    if args.attack == "all":
        run_all(args.gap)
    else:
        launch(args.attack)
