CREATE TABLE control_state (
 id INTEGER PRIMARY KEY CHECK(id=1),
 generation INTEGER NOT NULL DEFAULT 1 CHECK(generation > 0)
);
INSERT INTO control_state(id,generation) VALUES(1,1);

CREATE TABLE tunnel_sync_state (
 id INTEGER PRIMARY KEY CHECK(id=1),
 source_id TEXT NOT NULL DEFAULT '',
 last_sequence INTEGER NOT NULL DEFAULT 0,
 available INTEGER NOT NULL DEFAULT 0 CHECK(available IN (0,1)),
 last_success_at TEXT,
 last_error_at TEXT
);
INSERT INTO tunnel_sync_state(id) VALUES(1);

CREATE TABLE lifecycle_events (
 event_id TEXT PRIMARY KEY,
 source_id TEXT NOT NULL,
 sequence INTEGER NOT NULL,
 received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(source_id,sequence)
);

CREATE TABLE tunnel_event_cursor (
 tunnel_id TEXT PRIMARY KEY,
 source_id TEXT NOT NULL,
 sequence INTEGER NOT NULL,
 disconnected INTEGER NOT NULL DEFAULT 0 CHECK(disconnected IN (0,1))
);

CREATE TABLE telemetry_batches (
 event_id TEXT PRIMARY KEY,
 received_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

DROP INDEX active_tunnels_user_status;
DROP INDEX active_tunnels_key_status;
DROP INDEX active_tunnels_host_status;
ALTER TABLE active_tunnels RENAME TO active_tunnels_v2_old;
CREATE TABLE active_tunnels (
 id TEXT PRIMARY KEY,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 ssh_key_id INTEGER NOT NULL,
 protocol TEXT NOT NULL CHECK(protocol IN ('http','https','tcp','tls')),
 hostname TEXT NOT NULL DEFAULT '',
 tcp_port INTEGER NOT NULL DEFAULT 0 CHECK(tcp_port BETWEEN 0 AND 65535),
 source_ip TEXT NOT NULL DEFAULT '',
 generation INTEGER NOT NULL DEFAULT 1,
 event_sequence INTEGER NOT NULL DEFAULT 0,
 connected_at TEXT NOT NULL,
 disconnected_at TEXT,
 status TEXT NOT NULL CHECK(status IN ('active','disconnecting','stale','disconnected')),
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO active_tunnels(id,user_id,ssh_key_id,protocol,hostname,tcp_port,source_ip,generation,event_sequence,connected_at,disconnected_at,status,updated_at)
 SELECT id,user_id,ssh_key_id,protocol,hostname,tcp_port,source_ip,1,0,connected_at,disconnected_at,status,updated_at FROM active_tunnels_v2_old;
DROP TABLE active_tunnels_v2_old;
CREATE INDEX active_tunnels_user_status ON active_tunnels(user_id,status);
CREATE INDEX active_tunnels_key_status ON active_tunnels(ssh_key_id,status);
CREATE INDEX active_tunnels_host_status ON active_tunnels(hostname,status);
