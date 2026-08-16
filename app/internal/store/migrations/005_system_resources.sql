CREATE TABLE system_ssh_keys (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL UNIQUE,
 public_key TEXT NOT NULL,
 fingerprint TEXT NOT NULL UNIQUE,
 enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE system_subdomains (
 name TEXT PRIMARY KEY COLLATE NOCASE,
 system_key_id INTEGER NOT NULL REFERENCES system_ssh_keys(id) ON DELETE CASCADE,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

DROP INDEX active_tunnels_user_status;
DROP INDEX active_tunnels_key_status;
DROP INDEX active_tunnels_host_status;
ALTER TABLE active_tunnels RENAME TO active_tunnels_v4_old;
CREATE TABLE active_tunnels (
 id TEXT PRIMARY KEY,
 user_id INTEGER NOT NULL,
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
INSERT INTO active_tunnels SELECT * FROM active_tunnels_v4_old;
DROP TABLE active_tunnels_v4_old;
CREATE INDEX active_tunnels_user_status ON active_tunnels(user_id,status);
CREATE INDEX active_tunnels_key_status ON active_tunnels(ssh_key_id,status);
CREATE INDEX active_tunnels_host_status ON active_tunnels(hostname,status);
