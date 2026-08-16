package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"tunnel-control-plane/internal/model"
)

type AuditEntry struct {
	Actor, Target                                        *int64
	Action, ResourceType, ResourceID, SourceIP, Metadata string
}
type OutboxEvent struct {
	Kind, DedupeKey string
	Payload         any
}

func insertAudit(ctx context.Context, tx *sql.Tx, a AuditEntry) error {
	if a.Metadata == "" {
		a.Metadata = "{}"
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO audit_logs(actor_user_id,target_user_id,action,resource_type,resource_id,source_ip,metadata) VALUES(?,?,?,?,?,?,?)`, a.Actor, a.Target, a.Action, a.ResourceType, a.ResourceID, a.SourceIP, a.Metadata)
	return err
}
func insertOutbox(ctx context.Context, tx *sql.Tx, e OutboxEvent) error {
	b, err := json.Marshal(e.Payload)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO outbox(kind,dedupe_key,payload) VALUES(?,?,?) ON CONFLICT(dedupe_key) DO NOTHING`, e.Kind, e.DedupeKey, string(b))
	return err
}
func nextGeneration(ctx context.Context, tx *sql.Tx) (int64, error) {
	var g int64
	err := tx.QueryRowContext(ctx, `UPDATE control_state SET generation=generation+1 WHERE id=1 RETURNING generation`).Scan(&g)
	return g, err
}
func currentGenerationTx(ctx context.Context, tx *sql.Tx) (int64, error) {
	var g int64
	err := tx.QueryRowContext(ctx, `SELECT generation FROM control_state WHERE id=1`).Scan(&g)
	return g, err
}

// LoginDiscordAtomic creates the rotated session and its audit entry in the
// same transaction as the Discord profile update. Suspended users cannot race
// a login because the status predicate is checked while the write lock is held.
func (s *Store) LoginDiscordAtomic(ctx context.Context, discordID, username, displayName, email, avatar, role, sessionHash, csrf string, expires time.Time, sourceIP string) (*model.User, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO users(discord_id,username,display_name,email,avatar_url,role) VALUES(?,?,?,?,?,?) ON CONFLICT(discord_id) DO UPDATE SET username=excluded.username,display_name=excluded.display_name,email=excluded.email,avatar_url=excluded.avatar_url,role=excluded.role,updated_at=CURRENT_TIMESTAMP`, discordID, username, displayName, email, avatar, role)
	if err != nil {
		return nil, err
	}
	var u model.User
	var c, a string
	err = tx.QueryRowContext(ctx, `SELECT id,discord_id,username,display_name,email,avatar_url,role,status,created_at,updated_at FROM users WHERE discord_id=?`, discordID).Scan(&u.ID, &u.DiscordID, &u.Username, &u.DisplayName, &u.Email, &u.AvatarURL, &u.Role, &u.Status, &c, &a)
	if err != nil {
		return nil, err
	}
	u.CreatedAt = parseTime(c)
	u.UpdatedAt = parseTime(a)
	if u.Status != "active" {
		return nil, sql.ErrNoRows
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at) SELECT ?,id,?,? FROM users WHERE id=? AND status='active'`, sessionHash, csrf, expires.UTC().Format(time.RFC3339Nano), u.ID); err != nil {
		return nil, err
	}
	if err = insertAudit(ctx, tx, AuditEntry{Actor: &u.ID, Target: &u.ID, Action: "login", ResourceType: "session", SourceIP: sourceIP}); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) InsertKeyAtomic(ctx context.Context, uid int64, name, key, fp string, a AuditEntry) (int64, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx, `INSERT INTO ssh_keys(user_id,name,public_key,fingerprint) SELECT id,?,?,? FROM users WHERE id=? AND status='active'`, name, key, fp, uid)
	if err != nil {
		return 0, err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return 0, sql.ErrNoRows
	}
	id, err := r.LastInsertId()
	if err != nil {
		return 0, err
	}
	a.ResourceID = fmt.Sprint(id)
	if err = insertAudit(ctx, tx, a); err != nil {
		return 0, err
	}
	if err = insertOutbox(ctx, tx, OutboxEvent{Kind: "pubkey.write", DedupeKey: fmt.Sprintf("key:%d:write", id), Payload: map[string]any{"key_id": id}}); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}
func (s *Store) SetKeyEnabledAtomic(ctx context.Context, id int64, enabled bool, a AuditEntry) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current int
	err = tx.QueryRowContext(ctx, `SELECT k.enabled FROM ssh_keys k JOIN users u ON u.id=k.user_id WHERE k.id=? AND u.status='active'`, id).Scan(&current)
	if err != nil {
		return err
	}
	if (current == 1) == enabled {
		return tx.Commit()
	}
	g, err := nextGeneration(ctx, tx)
	if err != nil {
		return err
	}
	r, err := tx.ExecContext(ctx, `UPDATE ssh_keys SET enabled=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`, enabled, id)
	if err = requireAffected(r, err); err != nil {
		return err
	}
	if err = insertAudit(ctx, tx, a); err != nil {
		return err
	}
	kind := "pubkey.write"
	if !enabled {
		kind = "pubkey.remove"
	}
	if err = insertOutbox(ctx, tx, OutboxEvent{Kind: kind, DedupeKey: fmt.Sprintf("generation:%d:%s:key:%d", g, kind, id), Payload: map[string]any{"key_id": id, "generation": g}}); err != nil {
		return err
	}
	if !enabled {
		if _, err = tx.ExecContext(ctx, `UPDATE active_tunnels SET status='disconnecting',updated_at=CURRENT_TIMESTAMP WHERE ssh_key_id=? AND status IN ('active','stale')`, id); err != nil {
			return err
		}
		if err = insertOutbox(ctx, tx, OutboxEvent{Kind: "tunnel.disconnect_key", DedupeKey: fmt.Sprintf("generation:%d:disconnect:key:%d", g, id), Payload: map[string]any{"key_id": id, "generation": g}}); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *Store) DeleteKeyAtomic(ctx context.Context, id, userID int64, a AuditEntry) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	g, err := nextGeneration(ctx, tx)
	if err != nil {
		return err
	}
	for _, e := range []OutboxEvent{
		{Kind: "pubkey.remove", DedupeKey: fmt.Sprintf("generation:%d:remove:key:%d", g, id), Payload: map[string]any{"key_id": id, "user_id": userID, "generation": g}},
		{Kind: "tunnel.disconnect_key", DedupeKey: fmt.Sprintf("generation:%d:disconnect:key:%d", g, id), Payload: map[string]any{"key_id": id, "generation": g}},
	} {
		if err = insertOutbox(ctx, tx, e); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE active_tunnels SET status='disconnecting',updated_at=CURRENT_TIMESTAMP WHERE ssh_key_id=? AND status IN ('active','stale')`, id); err != nil {
		return err
	}
	if err = insertAudit(ctx, tx, a); err != nil {
		return err
	}
	r, err := tx.ExecContext(ctx, "DELETE FROM ssh_keys WHERE id=?", id)
	if err = requireAffected(r, err); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) InsertSubdomainAtomic(ctx context.Context, uid int64, name string, a AuditEntry) (int64, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx, `INSERT INTO subdomains(user_id,name) SELECT id,? FROM users WHERE id=? AND status='active'`, name, uid)
	if err != nil {
		return 0, err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return 0, sql.ErrNoRows
	}
	id, err := r.LastInsertId()
	if err != nil {
		return 0, err
	}
	a.ResourceID = fmt.Sprint(id)
	if err = insertAudit(ctx, tx, a); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}
func (s *Store) InsertTCPPortAtomic(ctx context.Context, uid int64, port int, a AuditEntry) (int64, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx, `INSERT INTO tcp_ports(user_id,port) SELECT id,? FROM users WHERE id=? AND status='active'`, port, uid)
	if err != nil {
		return 0, err
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return 0, sql.ErrNoRows
	}
	id, err := r.LastInsertId()
	if err != nil {
		return 0, err
	}
	if _, err = nextGeneration(ctx, tx); err != nil {
		return 0, err
	}
	a.ResourceID = fmt.Sprint(id)
	if err = insertAudit(ctx, tx, a); err != nil {
		return 0, err
	}
	return id, tx.Commit()
}
func (s *Store) DeleteTCPPortAtomic(ctx context.Context, id int64, port int, a AuditEntry) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	g, err := nextGeneration(ctx, tx)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE active_tunnels SET status='disconnecting',updated_at=CURRENT_TIMESTAMP WHERE protocol='tcp' AND tcp_port=? AND status IN ('active','stale')`, port); err != nil {
		return err
	}
	if err = insertOutbox(ctx, tx, OutboxEvent{Kind: "tunnel.disconnect_port", DedupeKey: fmt.Sprintf("generation:%d:disconnect:port:%d", g, port), Payload: map[string]any{"port": port, "generation": g}}); err != nil {
		return err
	}
	if err = insertAudit(ctx, tx, a); err != nil {
		return err
	}
	r, err := tx.ExecContext(ctx, "DELETE FROM tcp_ports WHERE id=? AND port=?", id, port)
	if err = requireAffected(r, err); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteSubdomainAtomic(ctx context.Context, id int64, name string, a AuditEntry) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	g, err := nextGeneration(ctx, tx)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE active_tunnels SET status='disconnecting',updated_at=CURRENT_TIMESTAMP WHERE (hostname=? OR hostname LIKE ?) AND status IN ('active','stale')`, name, name+".%"); err != nil {
		return err
	}
	if err = insertOutbox(ctx, tx, OutboxEvent{Kind: "tunnel.disconnect_host", DedupeKey: fmt.Sprintf("generation:%d:disconnect:host:%s", g, name), Payload: map[string]any{"hostname": name, "generation": g}}); err != nil {
		return err
	}
	if err = insertAudit(ctx, tx, a); err != nil {
		return err
	}
	r, err := tx.ExecContext(ctx, "DELETE FROM subdomains WHERE id=?", id)
	if err = requireAffected(r, err); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) SetUserStatusAtomic(ctx context.Context, id int64, status string, a AuditEntry) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current string
	if err = tx.QueryRowContext(ctx, `SELECT status FROM users WHERE id=?`, id).Scan(&current); err != nil {
		return err
	}
	if current == status {
		return tx.Commit()
	}
	expected := "active"
	if status == "active" {
		expected = "suspended"
	}
	g, err := nextGeneration(ctx, tx)
	if err != nil {
		return err
	}
	r, err := tx.ExecContext(ctx, `UPDATE users SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND status=?`, status, id, expected)
	if err = requireAffected(r, err); err != nil {
		return err
	}
	if status == "suspended" {
		if _, err = tx.ExecContext(ctx, "DELETE FROM sessions WHERE user_id=?", id); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE active_tunnels SET status='disconnecting',updated_at=CURRENT_TIMESTAMP WHERE user_id=? AND status IN ('active','stale')`, id); err != nil {
			return err
		}
		for _, e := range []OutboxEvent{{Kind: "tunnel.disconnect_user", DedupeKey: fmt.Sprintf("generation:%d:disconnect:user:%d", g, id), Payload: map[string]any{"user_id": id, "generation": g}}} {
			if err = insertOutbox(ctx, tx, e); err != nil {
				return err
			}
		}
	}
	if err = insertOutbox(ctx, tx, OutboxEvent{Kind: "pubkey.reconcile", DedupeKey: fmt.Sprintf("generation:%d:reconcile:user:%d", g, id), Payload: map[string]any{"generation": g}}); err != nil {
		return err
	}
	if err = insertAudit(ctx, tx, a); err != nil {
		return err
	}
	return tx.Commit()
}

// EnsureSystemResources registers the control-plane principal without creating a
// Discord user. Its negative key ID namespace cannot collide with user keys.
func (s *Store) EnsureSystemResources(ctx context.Context, name, publicKey, fingerprint, label string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var userConflict int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM subdomains WHERE name=?`, label).Scan(&userConflict); err != nil {
		return err
	}
	if userConflict != 0 {
		return fmt.Errorf("system subdomain %q conflicts with user reservation", label)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO system_ssh_keys(name,public_key,fingerprint) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET public_key=excluded.public_key,fingerprint=excluded.fingerprint,enabled=1,updated_at=CURRENT_TIMESTAMP`, name, publicKey, fingerprint)
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM system_subdomains WHERE system_key_id=(SELECT id FROM system_ssh_keys WHERE name=?) AND name<>?`, name, label); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO system_subdomains(name,system_key_id) SELECT ?,id FROM system_ssh_keys WHERE name=? ON CONFLICT(name) DO UPDATE SET system_key_id=excluded.system_key_id`, label, name)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// AuthorizeBind returns the current mutation generation. A later connect event
// must present the same generation; any intervening revocation makes it stale.
func (s *Store) AuthorizeBind(ctx context.Context, fingerprint, label, protocol string, port int) (model.SSHKey, int64, error) {
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return model.SSHKey{}, 0, err
	}
	defer tx.Rollback()
	var k model.SSHKey
	var enabled int
	var c, u string
	err = tx.QueryRowContext(ctx, `SELECT k.id,k.user_id,u.username,k.name,k.public_key,k.fingerprint,k.enabled,k.created_at,k.updated_at FROM ssh_keys k JOIN users u ON u.id=k.user_id WHERE k.fingerprint=? AND k.enabled=1 AND u.status='active'`, fingerprint).Scan(&k.ID, &k.UserID, &k.Owner, &k.Name, &k.PublicKey, &k.Fingerprint, &enabled, &c, &u)
	if errors.Is(err, sql.ErrNoRows) && (protocol == "http" || protocol == "https" || protocol == "tls") {
		var systemID int64
		err = tx.QueryRowContext(ctx, `SELECT k.id,k.name,k.public_key,k.fingerprint,k.created_at,k.updated_at FROM system_ssh_keys k JOIN system_subdomains d ON d.system_key_id=k.id WHERE k.fingerprint=? AND k.enabled=1 AND d.name=?`, fingerprint, label).Scan(&systemID, &k.Name, &k.PublicKey, &k.Fingerprint, &c, &u)
		if err == nil {
			k.ID, k.UserID, k.Owner, k.Enabled = -systemID, 0, "[system]", true
			k.CreatedAt, k.UpdatedAt = parseTime(c), parseTime(u)
			g, genErr := currentGenerationTx(ctx, tx)
			if genErr != nil {
				return model.SSHKey{}, 0, genErr
			}
			if genErr = tx.Commit(); genErr != nil {
				return model.SSHKey{}, 0, genErr
			}
			return k, g, nil
		}
	}
	if err != nil {
		return k, 0, err
	}
	k.Enabled = enabled == 1
	k.CreatedAt = parseTime(c)
	k.UpdatedAt = parseTime(u)
	if protocol == "http" || protocol == "https" || protocol == "tls" {
		var n int
		err = tx.QueryRowContext(ctx, `SELECT count(*) FROM subdomains WHERE user_id=? AND name=? AND status='reserved'`, k.UserID, label).Scan(&n)
		if err != nil || n != 1 {
			if err == nil {
				err = sql.ErrNoRows
			}
			return model.SSHKey{}, 0, err
		}
	} else if protocol == "tcp" && port >= model.PublicTCPPortMin && port <= model.PublicTCPPortMax {
		var n int
		err = tx.QueryRowContext(ctx, `SELECT count(*) FROM tcp_ports WHERE user_id=? AND port=?`, k.UserID, port).Scan(&n)
		if err != nil || n != 1 {
			if err == nil {
				err = sql.ErrNoRows
			}
			return model.SSHKey{}, 0, err
		}
	} else {
		return model.SSHKey{}, 0, sql.ErrNoRows
	}
	g, err := currentGenerationTx(ctx, tx)
	if err != nil {
		return model.SSHKey{}, 0, err
	}
	if err = tx.Commit(); err != nil {
		return model.SSHKey{}, 0, err
	}
	return k, g, nil
}

func validateLifecycleSource(ctx context.Context, tx *sql.Tx, sourceID string) error {
	if sourceID == "" {
		return errors.New("missing lifecycle source")
	}
	var current string
	if err := tx.QueryRowContext(ctx, `SELECT source_id FROM tunnel_sync_state WHERE id=1`).Scan(&current); err != nil {
		return err
	}
	var retired int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM retired_tunnel_sources WHERE source_id=?`, sourceID).Scan(&retired); err != nil {
		return err
	}
	if retired != 0 || (current != "" && current != sourceID) {
		return errors.New("stale lifecycle source")
	}
	return nil
}

func (s *Store) ApplyTunnelConnect(ctx context.Context, t model.ActiveTunnel, label, sourceID, eventID string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current int64
	if err = tx.QueryRowContext(ctx, `SELECT generation FROM control_state WHERE id=1`).Scan(&current); err != nil {
		return err
	}
	if t.Generation != current {
		return errors.New("stale authorization generation")
	}
	var valid int
	if t.Protocol == "http" || t.Protocol == "https" || t.Protocol == "tls" {
		if t.UserID == 0 && t.SSHKeyID < 0 {
			err = tx.QueryRowContext(ctx, `SELECT count(*) FROM system_ssh_keys k JOIN system_subdomains d ON d.system_key_id=k.id WHERE k.id=? AND k.enabled=1 AND d.name=?`, -t.SSHKeyID, label).Scan(&valid)
		} else {
			err = tx.QueryRowContext(ctx, `SELECT count(*) FROM ssh_keys k JOIN users u ON u.id=k.user_id JOIN subdomains d ON d.user_id=u.id WHERE k.id=? AND k.user_id=? AND k.enabled=1 AND u.status='active' AND d.name=?`, t.SSHKeyID, t.UserID, label).Scan(&valid)
		}
	} else if t.Protocol == "tcp" && t.TCPPort >= model.PublicTCPPortMin && t.TCPPort <= model.PublicTCPPortMax {
		err = tx.QueryRowContext(ctx, `SELECT count(*) FROM ssh_keys k JOIN users u ON u.id=k.user_id JOIN tcp_ports p ON p.user_id=u.id WHERE k.id=? AND k.user_id=? AND k.enabled=1 AND u.status='active' AND p.port=?`, t.SSHKeyID, t.UserID, t.TCPPort).Scan(&valid)
	} else {
		return sql.ErrNoRows
	}
	if err != nil {
		return err
	}
	if valid != 1 {
		return sql.ErrNoRows
	}
	if err = validateLifecycleSource(ctx, tx, sourceID); err != nil {
		return err
	}
	r, err := tx.ExecContext(ctx, `INSERT INTO lifecycle_events(event_id,source_id,sequence) VALUES(?,?,?) ON CONFLICT(event_id) DO NOTHING`, eventID, sourceID, t.EventSequence)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n == 0 {
		return tx.Commit()
	}
	r, err = tx.ExecContext(ctx, `INSERT INTO tunnel_event_cursor(tunnel_id,source_id,sequence,disconnected) VALUES(?,?,?,0) ON CONFLICT(tunnel_id) DO UPDATE SET source_id=excluded.source_id,sequence=excluded.sequence,disconnected=0 WHERE excluded.source_id<>tunnel_event_cursor.source_id OR excluded.sequence>tunnel_event_cursor.sequence`, t.ID, sourceID, t.EventSequence)
	if err != nil {
		return err
	}
	n, _ = r.RowsAffected()
	if n == 0 {
		return tx.Commit()
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO active_tunnels(id,user_id,ssh_key_id,protocol,hostname,tcp_port,source_ip,generation,event_sequence,connected_at,status) VALUES(?,?,?,?,?,?,?,?,?,?,'active') ON CONFLICT(id) DO UPDATE SET user_id=excluded.user_id,ssh_key_id=excluded.ssh_key_id,protocol=excluded.protocol,hostname=excluded.hostname,tcp_port=excluded.tcp_port,source_ip=excluded.source_ip,generation=excluded.generation,event_sequence=excluded.event_sequence,connected_at=excluded.connected_at,disconnected_at=NULL,status='active',updated_at=CURRENT_TIMESTAMP WHERE excluded.event_sequence>active_tunnels.event_sequence`, t.ID, t.UserID, t.SSHKeyID, t.Protocol, t.Hostname, t.TCPPort, t.SourceIP, t.Generation, t.EventSequence, t.ConnectedAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE tunnel_sync_state SET last_sequence=max(last_sequence,?) WHERE id=1`, t.EventSequence)
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) ApplyTunnelDisconnect(ctx context.Context, id, sourceID, eventID string, sequence int64, at time.Time) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = validateLifecycleSource(ctx, tx, sourceID); err != nil {
		return err
	}
	r, err := tx.ExecContext(ctx, `INSERT INTO lifecycle_events(event_id,source_id,sequence) VALUES(?,?,?) ON CONFLICT(event_id) DO NOTHING`, eventID, sourceID, sequence)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n == 0 {
		return tx.Commit()
	}
	r, err = tx.ExecContext(ctx, `INSERT INTO tunnel_event_cursor(tunnel_id,source_id,sequence,disconnected) VALUES(?,?,?,1) ON CONFLICT(tunnel_id) DO UPDATE SET source_id=excluded.source_id,sequence=excluded.sequence,disconnected=1 WHERE excluded.source_id<>tunnel_event_cursor.source_id OR excluded.sequence>tunnel_event_cursor.sequence`, id, sourceID, sequence)
	if err != nil {
		return err
	}
	n, _ = r.RowsAffected()
	if n == 0 {
		return tx.Commit()
	}
	_, err = tx.ExecContext(ctx, `UPDATE active_tunnels SET status='disconnected',event_sequence=?,disconnected_at=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND event_sequence<?`, sequence, at.UTC().Format(time.RFC3339Nano), id, sequence)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE tunnel_sync_state SET last_sequence=max(last_sequence,?) WHERE id=1`, sequence)
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) ReconcileActiveSnapshot(ctx context.Context, snapshot model.TunnelSnapshot, at time.Time) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var cursor int64
	var sourceID string
	if err = tx.QueryRowContext(ctx, `SELECT source_id,last_sequence FROM tunnel_sync_state WHERE id=1`).Scan(&sourceID, &cursor); err != nil {
		return err
	}
	if snapshot.SourceID == "" {
		return errors.New("missing snapshot source")
	}
	if snapshot.SourceID == sourceID && snapshot.Sequence < cursor {
		return errors.New("stale tunnel snapshot")
	}
	if snapshot.SourceID != sourceID {
		var retired int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM retired_tunnel_sources WHERE source_id=?`, snapshot.SourceID).Scan(&retired); err != nil {
			return err
		}
		if retired != 0 {
			return errors.New("retired tunnel snapshot source")
		}
		if sourceID != "" {
			if _, err = tx.ExecContext(ctx, `INSERT INTO retired_tunnel_sources(source_id) VALUES(?) ON CONFLICT DO NOTHING`, sourceID); err != nil {
				return err
			}
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM tunnel_event_cursor`); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE active_tunnels SET status='disconnected',disconnected_at=?,event_sequence=0,updated_at=CURRENT_TIMESTAMP WHERE status IN ('active','stale','disconnecting')`, at.UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE active_tunnels SET status='disconnected',disconnected_at=?,event_sequence=?,updated_at=CURRENT_TIMESTAMP WHERE status IN ('active','stale','disconnecting') AND event_sequence<=?`, at.UTC().Format(time.RFC3339Nano), snapshot.Sequence, snapshot.Sequence); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE tunnel_event_cursor SET sequence=?,disconnected=1 WHERE source_id=? AND sequence<=?`, snapshot.Sequence, snapshot.SourceID, snapshot.Sequence); err != nil {
		return err
	}
	for _, t := range snapshot.Tunnels {
		var valid int
		if t.Protocol == "http" || t.Protocol == "https" || t.Protocol == "tls" {
			label := t.Hostname
			if i := strings.IndexByte(label, '.'); i > 0 {
				label = label[:i]
			} else {
				continue
			}
			if t.UserID == 0 && t.SSHKeyID < 0 {
				err = tx.QueryRowContext(ctx, `SELECT count(*) FROM system_ssh_keys k JOIN system_subdomains d ON d.system_key_id=k.id WHERE k.id=? AND k.enabled=1 AND d.name=?`, -t.SSHKeyID, label).Scan(&valid)
			} else {
				err = tx.QueryRowContext(ctx, `SELECT count(*) FROM ssh_keys k JOIN users u ON u.id=k.user_id JOIN subdomains d ON d.user_id=u.id WHERE k.id=? AND k.user_id=? AND k.enabled=1 AND u.status='active' AND d.name=? AND d.status='reserved'`, t.SSHKeyID, t.UserID, label).Scan(&valid)
			}
		} else if t.Protocol == "tcp" && t.TCPPort >= model.PublicTCPPortMin && t.TCPPort <= model.PublicTCPPortMax {
			err = tx.QueryRowContext(ctx, `SELECT count(*) FROM ssh_keys k JOIN users u ON u.id=k.user_id JOIN tcp_ports p ON p.user_id=u.id WHERE k.id=? AND k.user_id=? AND k.enabled=1 AND u.status='active' AND p.port=?`, t.SSHKeyID, t.UserID, t.TCPPort).Scan(&valid)
		} else {
			continue
		}
		if err != nil {
			return err
		}
		if valid != 1 {
			continue
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO tunnel_event_cursor(tunnel_id,source_id,sequence,disconnected) VALUES(?,?,?,0) ON CONFLICT(tunnel_id) DO UPDATE SET source_id=excluded.source_id,sequence=excluded.sequence,disconnected=0`, t.ID, snapshot.SourceID, snapshot.Sequence); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO active_tunnels(id,user_id,ssh_key_id,protocol,hostname,tcp_port,source_ip,generation,event_sequence,connected_at,status) VALUES(?,?,?,?,?,?,?,?,?,?,'active') ON CONFLICT(id) DO UPDATE SET hostname=excluded.hostname,tcp_port=excluded.tcp_port,source_ip=excluded.source_ip,generation=excluded.generation,event_sequence=excluded.event_sequence,disconnected_at=NULL,status='active',updated_at=CURRENT_TIMESTAMP WHERE excluded.event_sequence>=active_tunnels.event_sequence`, t.ID, t.UserID, t.SSHKeyID, t.Protocol, t.Hostname, t.TCPPort, t.SourceIP, t.Generation, snapshot.Sequence, t.ConnectedAt.UTC().Format(time.RFC3339Nano))
		if err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE tunnel_sync_state SET source_id=?,last_sequence=?,available=1,last_success_at=?,last_error_at=NULL WHERE id=1`, snapshot.SourceID, snapshot.Sequence, at.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) MarkTunnelSyncUnavailable(ctx context.Context, at time.Time) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE active_tunnels SET status='stale',updated_at=CURRENT_TIMESTAMP WHERE status='active'`); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE tunnel_sync_state SET available=0,last_error_at=? WHERE id=1`, at.UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) TunnelSyncState(ctx context.Context) (model.TunnelSyncState, error) {
	var v model.TunnelSyncState
	var a int
	var ok, fail sql.NullString
	err := s.DB.QueryRowContext(ctx, `SELECT available,last_sequence,last_success_at,last_error_at FROM tunnel_sync_state WHERE id=1`).Scan(&a, &v.LastSequence, &ok, &fail)
	v.Available = a == 1
	if ok.Valid {
		v.LastSuccessAt = parseTime(ok.String)
	}
	if fail.Valid {
		v.LastErrorAt = parseTime(fail.String)
	}
	return v, err
}
func (s *Store) ActiveTunnels(ctx context.Context, userID *int64) ([]model.ActiveTunnel, error) {
	out, _, err := s.ActiveTunnelsPage(ctx, userID, 0, 0)
	return out, err
}
func (s *Store) ActiveTunnelsPage(ctx context.Context, userID *int64, limit, offset int) ([]model.ActiveTunnel, bool, error) {
	q := `SELECT t.id,t.user_id,t.ssh_key_id,COALESCE(u.username,'[system]'),COALESCE(k.name,sk.name,'[revoked]'),t.protocol,t.hostname,t.tcp_port,t.source_ip,t.status,t.generation,t.event_sequence,t.connected_at,COALESCE(t.disconnected_at,'') FROM active_tunnels t LEFT JOIN users u ON u.id=t.user_id LEFT JOIN ssh_keys k ON k.id=t.ssh_key_id LEFT JOIN system_ssh_keys sk ON sk.id=-t.ssh_key_id AND t.user_id=0 WHERE t.status!='disconnected'`
	args := []any{}
	if userID != nil {
		q += " AND t.user_id=?"
		args = append(args, *userID)
	}
	q += " ORDER BY t.connected_at DESC,t.id DESC"
	if limit > 0 {
		q += " LIMIT ? OFFSET ?"
		args = append(args, limit+1, offset)
	}
	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var out []model.ActiveTunnel
	for rows.Next() {
		var t model.ActiveTunnel
		var c, d string
		if err = rows.Scan(&t.ID, &t.UserID, &t.SSHKeyID, &t.Owner, &t.KeyName, &t.Protocol, &t.Hostname, &t.TCPPort, &t.SourceIP, &t.Status, &t.Generation, &t.EventSequence, &c, &d); err != nil {
			return nil, false, err
		}
		t.ConnectedAt = parseTime(c)
		t.DisconnectedAt = parseTime(d)
		out = append(out, t)
	}
	if err = rows.Err(); err != nil {
		return nil, false, err
	}
	hasMore := limit > 0 && len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}

func (s *Store) PendingOutbox(ctx context.Context, limit int) ([]model.OutboxItem, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id,kind,dedupe_key,payload,attempts,available_at FROM outbox WHERE completed_at IS NULL AND available_at<=? ORDER BY id LIMIT ?`, time.Now().UTC().Format(time.RFC3339Nano), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.OutboxItem
	for rows.Next() {
		var i model.OutboxItem
		var a string
		if err = rows.Scan(&i.ID, &i.Kind, &i.DedupeKey, &i.Payload, &i.Attempts, &a); err != nil {
			return nil, err
		}
		i.AvailableAt = parseTime(a)
		out = append(out, i)
	}
	return out, rows.Err()
}
func (s *Store) CompleteOutbox(ctx context.Context, id int64) error {
	r, err := s.DB.ExecContext(ctx, `UPDATE outbox SET completed_at=CURRENT_TIMESTAMP,last_error='' WHERE id=? AND completed_at IS NULL`, id)
	return requireAffected(r, err)
}
func (s *Store) RetryOutbox(ctx context.Context, id int64, attempts int, lastErr string) error {
	if len(lastErr) > 500 {
		lastErr = lastErr[:500]
	}
	delay := time.Second << min(attempts, 8)
	if delay > 5*time.Minute {
		delay = 5 * time.Minute
	}
	_, err := s.DB.ExecContext(ctx, `UPDATE outbox SET attempts=?,available_at=?,last_error=? WHERE id=? AND completed_at IS NULL`, attempts, time.Now().Add(delay).UTC().Format(time.RFC3339Nano), lastErr, id)
	return err
}
func (s *Store) PendingOutboxCount(ctx context.Context) (int, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, `SELECT count(*) FROM outbox WHERE completed_at IS NULL`).Scan(&n)
	return n, err
}
func (s *Store) CleanupSecurityTelemetry(ctx context.Context, now time.Time) error {
	cutoff := now.UTC().Add(-90 * 24 * time.Hour)
	_, metricsErr := s.DB.ExecContext(ctx, `DELETE FROM security_telemetry WHERE bucket_start<?`, cutoff.Format(time.RFC3339))
	_, batchesErr := s.DB.ExecContext(ctx, `DELETE FROM telemetry_batches WHERE received_at<?`, cutoff.Format("2006-01-02 15:04:05"))
	return errors.Join(metricsErr, batchesErr)
}
func (s *Store) AddSecurityTelemetryBatch(ctx context.Context, eventID string, events map[string]int64) error {
	if eventID == "" || len(events) == 0 {
		return errors.New("invalid telemetry batch")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx, `INSERT INTO telemetry_batches(event_id) VALUES(?) ON CONFLICT DO NOTHING`, eventID)
	if err != nil {
		return err
	}
	n, _ := r.RowsAffected()
	if n == 0 {
		return tx.Commit()
	}
	now := time.Now().UTC()
	cutoff := now.Add(-90 * 24 * time.Hour)
	if _, err = tx.ExecContext(ctx, `DELETE FROM security_telemetry WHERE bucket_start<?`, cutoff.Format(time.RFC3339)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM telemetry_batches WHERE received_at<?`, cutoff.Format("2006-01-02 15:04:05")); err != nil {
		return err
	}
	bucket := now.Truncate(time.Minute).Format(time.RFC3339)
	for event, count := range events {
		if event == "" || count < 1 {
			return errors.New("invalid telemetry")
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO security_telemetry(bucket_start,event_type,count) VALUES(?,?,?) ON CONFLICT(bucket_start,event_type) DO UPDATE SET count=count+excluded.count`, bucket, event, count); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *Store) AddSecurityTelemetry(ctx context.Context, event string, count int64) error {
	return s.AddSecurityTelemetryBatch(ctx, fmt.Sprintf("legacy-%d", time.Now().UnixNano()), map[string]int64{event: count})
}
func (s *Store) RecentSecurityTelemetry(ctx context.Context, limit int) ([]model.SecurityMetric, error) {
	out, _, err := s.SecurityTelemetryPage(ctx, limit, 0)
	return out, err
}
func (s *Store) SecurityTelemetryPage(ctx context.Context, limit, offset int) ([]model.SecurityMetric, bool, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT bucket_start,event_type,count FROM security_telemetry WHERE event_type<>'unknown_host' ORDER BY bucket_start DESC,event_type LIMIT ? OFFSET ?`, limit+1, offset)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var out []model.SecurityMetric
	for rows.Next() {
		var m model.SecurityMetric
		var b string
		if err = rows.Scan(&b, &m.EventType, &m.Count); err != nil {
			return nil, false, err
		}
		m.BucketStart = parseTime(b)
		out = append(out, m)
	}
	if err = rows.Err(); err != nil {
		return nil, false, err
	}
	hasMore := len(out) > limit
	if hasMore {
		out = out[:limit]
	}
	return out, hasMore, nil
}
