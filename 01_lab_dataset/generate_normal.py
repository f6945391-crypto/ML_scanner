"""
generate_normal.py — Genera TRÁFICO NORMAL variado contra el ESP32 (clase benigna).

Objetivo: que el AE aprenda la VARIEDAD del comportamiento legítimo, no una única forma.
Mezcla cadencias, recursos y ráfagas. Correr ANTES y en paralelo a la captura en modo collect,
SIN ataques activos (esta ventana es 100% benigna).

MiniMax: implementa los TODO. No usar concurrencia agresiva (esto es tráfico normal, no flood).
"""
from __future__ import annotations
import argparse, subprocess, time, random, sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))
import config  # noqa: E402

BASE = f"http://{config.ESP32_IP}"
RESOURCES = ["/info", "/status", "/wot", "/hello"]   # recursos del L6


def one_request(path: str) -> None:
    """Una petición legítima con curl. Silencia salida y desactiva proxy (auditoría: el proxy
    de la laptop puede interceptar el tráfico al ESP32)."""
    try:
        subprocess.run(["curl", "-s", "--noproxy", "*", "-o", "/dev/null", BASE + path],
                       timeout=5, check=False)
    except (subprocess.TimeoutExpired, OSError):
        pass


def run(minutes: float) -> None:
    """Bucle de tráfico normal con patrón realista durante 'minutes'.
    TODO (patrón sugerido, variar para dar variedad):
      - loop hasta agotar el tiempo:
          * elegir recurso aleatorio de RESOURCES
          * one_request(recurso)
          * dormir un intervalo aleatorio: la mayoría 1-5 s, a veces ráfaga corta (0.1-0.3 s)
          * cada cierto tiempo, una pausa larga (10-20 s) simulando inactividad
      - imprimir cada N peticiones un contador de progreso
    """
    t_fin = time.time() + minutes * 60.0
    n = 0
    while time.time() < t_fin:
        one_request(random.choice(RESOURCES))
        n += 1
        r = random.random()
        if r < 0.10:
            time.sleep(random.uniform(0.1, 0.3))      # ráfaga corta
        elif r < 0.90:
            time.sleep(random.uniform(1.0, 5.0))      # cadencia normal
        else:
            time.sleep(random.uniform(10.0, 20.0))    # inactividad
        if n % 20 == 0:
            print(f"[normal] {n} peticiones; quedan {int(t_fin - time.time())} s")
    print(f"[normal] fin: {n} peticiones benignas")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--minutes", type=float, default=30.0)
    args = ap.parse_args()
    print(f"[normal] generando tráfico benigno {args.minutes} min contra {BASE}")
    run(args.minutes)
