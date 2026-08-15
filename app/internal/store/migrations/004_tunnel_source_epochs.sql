CREATE TABLE retired_tunnel_sources (
 source_id TEXT PRIMARY KEY,
 retired_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
