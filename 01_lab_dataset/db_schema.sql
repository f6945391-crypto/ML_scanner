-- db_schema.sql — esquema SQLite del testbed. Aplicar con:
--   sqlite3 traffic.db < db_schema.sql
-- Tres tablas: flows (dataset), attack_windows (ground truth), events (inferencia en vivo).

-- Flujos agregados desde la captura (capa 1). Un registro por flujo (5-tupla+timeout).
CREATE TABLE IF NOT EXISTS flows (
    flow_id        TEXT PRIMARY KEY,   -- hash(5-tupla + ts_start)
    ts_start       REAL NOT NULL,      -- epoch segundos, primer paquete
    ts_end         REAL NOT NULL,      -- epoch segundos, último paquete
    src_ip         TEXT,
    dst_ip         TEXT,
    src_port       INTEGER,
    dst_port       INTEGER,
    protocol       INTEGER,            -- 6=TCP 17=UDP 1=ICMP
    duration_ms    REAL,
    in_bytes       INTEGER,
    out_bytes      INTEGER,
    in_pkts        INTEGER,
    out_pkts       INTEGER,
    tcp_flags      INTEGER,            -- OR acumulado de flags
    pkts_per_s     REAL,
    bytes_per_pkt  REAL,
    iat_mean_ms    REAL,
    label          INTEGER DEFAULT 0,  -- 0=normal 1=ataque (lo pone label_flows.py)
    attack_family  TEXT DEFAULT 'benign'
);
CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(ts_start);

-- Ventanas de ataque registradas por simulate_attacks.py (ground truth por construcción).
CREATE TABLE IF NOT EXISTS attack_windows (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    family         TEXT NOT NULL,      -- 'synflood' | 'httpflood' | 'portscan'
    ts_start       REAL NOT NULL,
    ts_end         REAL NOT NULL,
    target_ip      TEXT,
    tool_cmd       TEXT                -- comando exacto lanzado (trazabilidad)
);

-- Eventos de inferencia en vivo (capa 3). Alimenta el dashboard y la validación post-hoc.
-- AUDITORÍA C2/§4b (2026-07-05): se añaden src_ip y pkts_per_s para el panel de throughput
-- por cliente del dashboard (atacante vs cliente normal). En una BD existente aplicar:
--   ALTER TABLE events ADD COLUMN src_ip TEXT;
--   ALTER TABLE events ADD COLUMN pkts_per_s REAL;
CREATE TABLE IF NOT EXISTS events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ts             REAL NOT NULL,
    flow_id        TEXT,
    src_ip         TEXT,               -- cliente origen del flujo (throughput por usuario)
    score          REAL,               -- error de reconstrucción
    threshold      REAL,
    anomaly        INTEGER,            -- 0/1 según score>threshold
    attack_family  TEXT,               -- si se conoce (durante demo controlada)
    pkts_per_s     REAL                -- tasa del flujo (panel de throughput del dashboard)
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
