CREATE TABLE active_tunnels (
 id TEXT PRIMARY KEY,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 ssh_key_id INTEGER NOT NULL REFERENCES ssh_keys(id) ON DELETE CASCADE,
 protocol TEXT NOT NULL CHECK(protocol IN ('http','https','tcp','tls')),
 hostname TEXT NOT NULL DEFAULT '',
 tcp_port INTEGER NOT NULL DEFAULT 0 CHECK(tcp_port BETWEEN 0 AND 65535),
 source_ip TEXT NOT NULL DEFAULT '',
 connected_at TEXT NOT NULL,
 disconnected_at TEXT,
 status TEXT NOT NULL CHECK(status IN ('active','disconnected')),
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX active_tunnels_user_status ON active_tunnels(user_id,status);
CREATE INDEX active_tunnels_key_status ON active_tunnels(ssh_key_id,status);
CREATE INDEX active_tunnels_host_status ON active_tunnels(hostname,status);

CREATE TABLE security_telemetry (
 bucket_start TEXT NOT NULL,
 event_type TEXT NOT NULL,
 count INTEGER NOT NULL DEFAULT 0 CHECK(count >= 0),
 PRIMARY KEY(bucket_start,event_type)
);

CREATE TABLE outbox (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 kind TEXT NOT NULL,
 dedupe_key TEXT NOT NULL UNIQUE,
 payload TEXT NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0,
 available_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 last_error TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 completed_at TEXT
);
CREATE INDEX outbox_pending ON outbox(completed_at,available_at,id);
