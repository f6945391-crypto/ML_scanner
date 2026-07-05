"""
config.py — Configuración compartida por TODAS las capas del proyecto IoT AE-IDS.

Este archivo es el ÚNICO lugar donde se define el contrato de datos y los parámetros.
Ninguna otra parte del código debe hard-codear nombres de features, rutas ni umbrales:
todo se importa desde aquí. Así, si cambia una feature, cambia en un solo sitio.

NO requiere dependencias externas (solo stdlib), para poder importarse en cualquier máquina.
"""
from pathlib import Path

# --- Rutas (relativas a la raíz del proyecto) --------------------------------
ROOT = Path(__file__).resolve().parent
DB_PATH        = ROOT / "01_lab_dataset" / "traffic.db"        # SQLite en operación
DATASET_NORMAL = ROOT / "01_lab_dataset" / "dataset_normal.csv"  # solo benigno → entrenar AE
DATASET_TEST   = ROOT / "01_lab_dataset" / "dataset_test.csv"    # benigno+ataque → validar
ARTIFACTS_DIR  = ROOT / "03_realtime_ae" / "artifacts"
MODEL_PATH     = ARTIFACTS_DIR / "modelo.pt"
SCALER_PATH    = ARTIFACTS_DIR / "scaler.pkl"
THRESHOLD_PATH = ARTIFACTS_DIR / "umbral.json"
META_PATH      = ARTIFACTS_DIR / "meta.json"

# --- Red / testbed -----------------------------------------------------------
ESP32_IP   = "10.42.0.98"      # <-- AJUSTAR a la IP real del ESP32 (ver /status del L6)
CAPTURE_IFACE = "wlo1"          # <-- AJUSTAR a la interfaz de la laptop en esa red
FLOW_TIMEOUT_S = 60.0            # inactividad que cierra un flujo (concepto NetFlow)

# --- CONTRATO DE DATOS (congelado) -------------------------------------------
# Vector de entrada del AE, en este orden EXACTO. No reordenar.
FEATURE_COLS = [
    "src_port", "dst_port", "protocol",
    "duration_ms", "in_bytes", "out_bytes", "in_pkts", "out_pkts",
    "tcp_flags", "pkts_per_s", "bytes_per_pkt",  # 11 features
]
# 'iat_mean_ms' se calcula y guarda pero queda como feature OPCIONAL (ver ablación);
# si se activa, añadirla aquí y re-entrenar. Mantener 11 por defecto para el AE base.

# Features a transformar con log1p (colas largas), igual que en el proyecto NF-ToN-IoT
LOG_FEATURES = ["in_bytes", "out_bytes", "in_pkts", "out_pkts", "duration_ms", "pkts_per_s"]

# Features categóricas (candidatas a fuga/atajo -> ablación con/sin puertos)
CATEGORICAL_HINT = ["src_port", "dst_port", "protocol", "tcp_flags"]

META_COLS = ["flow_id", "ts_start", "label", "attack_family"]

# --- Modelo AE ---------------------------------------------------------------
LATENT_DIM = 4          # cuello de botella real (ver informe crítico: no usar 8 con ~11 features)
ENC_HIDDEN = [32, 16]
DEC_HIDDEN = [16, 32]
EPOCHS     = 60
BATCH_SIZE = 512
LR         = 5e-4
PATIENCE   = 7
SEED       = 42

# --- Umbral ------------------------------------------------------------------
# Método por defecto para fijar tau sobre el error de reconstrucción del normal de validación.
THRESHOLD_METHOD = "P99"     # opciones: "P95","P99","mu+1sigma","mu+2sigma","mu+3sigma"

# --- Servicio Flask ----------------------------------------------------------
SERVICE_HOST = "127.0.0.1"
SERVICE_PORT = 8080

# --- Ataques de la demo (alcance fijado) -------------------------------------
ATTACK_FAMILIES = ["benign", "synflood", "httpflood", "portscan"]
