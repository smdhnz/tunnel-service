package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"tunnel-control-plane/internal/model"
)

func hardeningStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "hardening.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func seedIdentity(t *testing.T, s *Store, discord, fp, domain string) (int64, int64) {
	t.Helper()
	u, err := s.UpsertDiscordUser(context.Background(), discord, discord, discord, "", "", "user")
	if err != nil {
		t.Fatal(err)
	}
	k, err := s.DB.Exec(`INSERT INTO ssh_keys(user_id,name,public_key,fingerprint) VALUES(?,?,?,?)`, u.ID, "key", "ssh-ed25519 AAAA", fp)
	if err != nil {
		t.Fatal(err)
	}
	kid, _ := k.LastInsertId()
	if domain != "" {
		if _, err = s.DB.Exec(`INSERT INTO subdomains(user_id,name) VALUES(?,?)`, u.ID, domain); err != nil {
			t.Fatal(err)
		}
	}
	return u.ID, kid
}
func TestSecurityTelemetryRetentionAndPagination(t *testing.T) {
	ctx := context.Background()
	s := hardeningStore(t)
	old := time.Now().UTC().Add(-91 * 24 * time.Hour).Format(time.RFC3339)
	recent := time.Now().UTC().Add(-time.Hour).Truncate(time.Minute).Format(time.RFC3339)
	if _, err := s.DB.Exec(`INSERT INTO security_telemetry(bucket_start,event_type,count) VALUES(?,?,?), (?,?,?)`, old, "unknown_host", 1, recent, "rate_limited", 2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`INSERT INTO telemetry_batches(event_id,received_at) VALUES(?,?)`, "old-batch", old); err != nil {
		t.Fatal(err)
	}
	if err := s.AddSecurityTelemetryBatch(ctx, "new-batch", map[string]int64{"unknown_host": 3}); err != nil {
		t.Fatal(err)
	}
	var oldMetrics, oldBatches int
	if err := s.DB.QueryRow(`SELECT count(*) FROM security_telemetry WHERE bucket_start=?`, old).Scan(&oldMetrics); err != nil {
		t.Fatal(err)
	}
	if err := s.DB.QueryRow(`SELECT count(*) FROM telemetry_batches WHERE event_id='old-batch'`).Scan(&oldBatches); err != nil {
		t.Fatal(err)
	}
	if oldMetrics != 0 || oldBatches != 0 {
		t.Fatalf("expired telemetry remains: metrics=%d batches=%d", oldMetrics, oldBatches)
	}
	var retainedUnknownHosts int
	if err := s.DB.QueryRow(`SELECT count(*) FROM security_telemetry WHERE event_type='unknown_host'`).Scan(&retainedUnknownHosts); err != nil {
		t.Fatal(err)
	}
	if retainedUnknownHosts != 1 {
		t.Fatalf("unknown-host telemetry was not retained: %d", retainedUnknownHosts)
	}
	first, more, err := s.SecurityTelemetryPage(ctx, 1, 0)
	if err != nil || len(first) != 1 || more || first[0].EventType == "unknown_host" {
		t.Fatalf("visible security page=%+v more=%v err=%v", first, more, err)
	}
}

func TestTCPPortRangeConstraint(t *testing.T) {
	s := hardeningStore(t)
	uid, _ := seedIdentity(t, s, "range", "SHA256:range", "")
	for _, port := range []int{model.PublicTCPPortMin, model.PublicTCPPortMax} {
		if _, err := s.DB.Exec(`INSERT INTO tcp_ports(user_id,port) VALUES(?,?)`, uid, port); err != nil {
			t.Fatalf("valid port %d rejected: %v", port, err)
		}
	}
	for _, port := range []int{model.PublicTCPPortMin - 1, model.PublicTCPPortMax + 1} {
		if _, err := s.DB.Exec(`INSERT INTO tcp_ports(user_id,port) VALUES(?,?)`, uid, port); err == nil {
			t.Fatalf("out-of-range port %d accepted", port)
		}
	}
}

func TestAuthorizeBindOwnershipEnabledAndActive(t *testing.T) {
	ctx := context.Background()
	s := hardeningStore(t)
	uid, kid := seedIdentity(t, s, "alice", "SHA256:alice", "mine")
	other, _ := seedIdentity(t, s, "bob", "SHA256:bob", "other")
	k, generation, err := s.AuthorizeBind(ctx, "SHA256:alice", "mine", "http", 80)
	if err != nil || generation < 1 || k.ID != kid || k.UserID != uid {
		t.Fatalf("valid rejected: %+v %v", k, err)
	}
	for _, port := range []int{model.PublicTCPPortMin, 25565, model.PublicTCPPortMax} {
		if _, err = s.DB.Exec(`INSERT INTO tcp_ports(user_id,port) VALUES(?,?)`, uid, port); err != nil {
			t.Fatal(err)
		}
		if tcpKey, _, tcpErr := s.AuthorizeBind(ctx, "SHA256:alice", "", "tcp", port); tcpErr != nil || tcpKey.UserID != uid {
			t.Fatalf("reserved TCP %d rejected: key=%+v err=%v", port, tcpKey, tcpErr)
		}
	}
	for name, fn := range map[string]func(){"manual": func() { _, _, err = s.AuthorizeBind(ctx, "SHA256:manual", "mine", "http", 80) }, "other owner": func() { _, _, err = s.AuthorizeBind(ctx, "SHA256:alice", "other", "https", 443) }, "below tcp range": func() { _, _, err = s.AuthorizeBind(ctx, "SHA256:alice", "", "tcp", model.PublicTCPPortMin-1) }, "above tcp range": func() { _, _, err = s.AuthorizeBind(ctx, "SHA256:alice", "", "tcp", model.PublicTCPPortMax+1) }, "unreserved tcp": func() { _, _, err = s.AuthorizeBind(ctx, "SHA256:alice", "", "tcp", 25566) }, "other owner tcp": func() { _, _, err = s.AuthorizeBind(ctx, "SHA256:bob", "", "tcp", 25565) }} {
		t.Run(name, func(t *testing.T) {
			fn()
			if !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("allowed: %v", err)
			}
		})
	}
	if _, err = s.DB.Exec(`UPDATE ssh_keys SET enabled=0 WHERE id=?`, kid); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.AuthorizeBind(ctx, "SHA256:alice", "mine", "http", 80); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("disabled allowed: %v", err)
	}
	if _, err = s.DB.Exec(`UPDATE ssh_keys SET enabled=1 WHERE id=?`, kid); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec(`UPDATE users SET status='suspended' WHERE id=?`, uid); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.AuthorizeBind(ctx, "SHA256:alice", "mine", "http", 80); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("suspended allowed: %v", err)
	}
	_ = other
}
func TestActiveTunnelLifecycleAndOwnershipFilter(t *testing.T) {
	ctx := context.Background()
	s := hardeningStore(t)
	u1, k1 := seedIdentity(t, s, "alice", "fp1", "a")
	u2, k2 := seedIdentity(t, s, "bob", "fp2", "b")
	now := time.Now().UTC()
	for _, v := range []struct {
		id   string
		u, k int64
		host string
	}{{"t1", u1, k1, "a"}, {"t2", u2, k2, "b"}} {
		if err := s.ApplyTunnelConnect(ctx, modelTunnel(v.id, v.u, v.k, v.host+".example.com", now), v.host, "source-1", "connect-"+v.id); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.ActiveTunnels(ctx, &u1)
	if err != nil || len(got) != 1 || got[0].ID != "t1" {
		t.Fatalf("ownership filter: %+v %v", got, err)
	}
	if err = s.ApplyTunnelDisconnect(ctx, "t1", "source-1", "disconnect-t1", 3, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	got, _ = s.ActiveTunnels(ctx, nil)
	if len(got) != 1 || got[0].ID != "t2" {
		t.Fatalf("lifecycle: %+v", got)
	}
}
func modelTunnel(id string, u, k int64, h string, at time.Time) model.ActiveTunnel {
	seq := int64(1)
	if id == "t2" {
		seq = 2
	}
	return model.ActiveTunnel{ID: id, UserID: u, SSHKeyID: k, Protocol: "http", Hostname: h, TCPPort: 80, Generation: 1, EventSequence: seq, ConnectedAt: at}
}

func TestTCPConnectAndSnapshotEnforcePublicRange(t *testing.T) {
	ctx := context.Background()
	s := hardeningStore(t)
	uid, keyID := seedIdentity(t, s, "tcp-range", "SHA256:tcp-range", "")
	if _, err := s.DB.Exec(`INSERT INTO tcp_ports(user_id,port) VALUES(?,?)`, uid, model.PublicTCPPortMin); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, port := range []int{model.PublicTCPPortMin - 1, model.PublicTCPPortMax + 1} {
		tunnel := model.ActiveTunnel{ID: fmt.Sprintf("connect-%d", port), UserID: uid, SSHKeyID: keyID, Protocol: "tcp", TCPPort: port, Generation: 1, EventSequence: 1, ConnectedAt: now}
		if err := s.ApplyTunnelConnect(ctx, tunnel, "", "tcp-range-source", fmt.Sprintf("event-%d", port)); !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("out-of-range connect %d: %v", port, err)
		}
	}
	valid := model.ActiveTunnel{ID: "snapshot-valid", UserID: uid, SSHKeyID: keyID, Protocol: "tcp", TCPPort: model.PublicTCPPortMin, Generation: 1, ConnectedAt: now}
	snapshot := model.TunnelSnapshot{SourceID: "tcp-range-source", Sequence: 2, Tunnels: []model.ActiveTunnel{
		valid,
		{ID: "snapshot-below", UserID: uid, SSHKeyID: keyID, Protocol: "tcp", TCPPort: model.PublicTCPPortMin - 1, Generation: 1, ConnectedAt: now},
		{ID: "snapshot-above", UserID: uid, SSHKeyID: keyID, Protocol: "tcp", TCPPort: model.PublicTCPPortMax + 1, Generation: 1, ConnectedAt: now},
	}}
	if err := s.ReconcileActiveSnapshot(ctx, snapshot, now); err != nil {
		t.Fatal(err)
	}
	got, err := s.ActiveTunnels(ctx, nil)
	if err != nil || len(got) != 1 || got[0].ID != valid.ID {
		t.Fatalf("out-of-range snapshot entries not ignored: tunnels=%+v err=%v", got, err)
	}
}

func TestTCPPortDelayedReleaseDoesNotInvalidateRereservation(t *testing.T) {
	ctx := context.Background()
	s := hardeningStore(t)
	oldUID, oldKeyID := seedIdentity(t, s, "old-tcp", "old-tcp-fp", "")
	newUID, newKeyID := seedIdentity(t, s, "new-tcp", "new-tcp-fp", "")
	id, err := s.InsertTCPPortAtomic(ctx, oldUID, 25565, AuditEntry{Actor: &oldUID, Target: &oldUID, Action: "reserve", ResourceType: "tcp_port"})
	if err != nil {
		t.Fatal(err)
	}
	_, oldGeneration, err := s.AuthorizeBind(ctx, "old-tcp-fp", "", "tcp", 25565)
	if err != nil {
		t.Fatal(err)
	}
	oldTunnel := model.ActiveTunnel{ID: "old-tcp-tunnel", UserID: oldUID, SSHKeyID: oldKeyID, Protocol: "tcp", TCPPort: 25565, Generation: oldGeneration, EventSequence: 1, ConnectedAt: time.Now()}
	if err = s.ApplyTunnelConnect(ctx, oldTunnel, "", "tcp-source", "old-tcp-connect"); err != nil {
		t.Fatal(err)
	}
	if err = s.DeleteTCPPortAtomic(ctx, id, 25565, AuditEntry{Actor: &oldUID, Target: &oldUID, Action: "release", ResourceType: "tcp_port"}); err != nil {
		t.Fatal(err)
	}
	var kind string
	var disconnectGeneration int64
	if err = s.DB.QueryRow(`SELECT kind,json_extract(payload,'$.generation') FROM outbox WHERE completed_at IS NULL`).Scan(&kind, &disconnectGeneration); err != nil || kind != "tunnel.disconnect_port" {
		t.Fatalf("outbox kind=%q generation=%d err=%v", kind, disconnectGeneration, err)
	}
	if _, err = s.InsertTCPPortAtomic(ctx, newUID, 25565, AuditEntry{Actor: &newUID, Target: &newUID, Action: "reserve", ResourceType: "tcp_port"}); err != nil {
		t.Fatal(err)
	}
	_, newGeneration, err := s.AuthorizeBind(ctx, "new-tcp-fp", "", "tcp", 25565)
	if err != nil {
		t.Fatal(err)
	}
	if newGeneration <= disconnectGeneration {
		t.Fatalf("re-reservation generation=%d disconnect generation=%d", newGeneration, disconnectGeneration)
	}
	if err = s.ApplyTunnelConnect(ctx, model.ActiveTunnel{ID: "late-old-tcp", UserID: oldUID, SSHKeyID: oldKeyID, Protocol: "tcp", TCPPort: 25565, Generation: oldGeneration, EventSequence: 2, ConnectedAt: time.Now()}, "", "tcp-source", "late-old-tcp-connect"); err == nil {
		t.Fatal("late old TCP registration accepted after release")
	}
	newTunnel := model.ActiveTunnel{ID: "new-tcp-tunnel", UserID: newUID, SSHKeyID: newKeyID, Protocol: "tcp", TCPPort: 25565, Generation: newGeneration, EventSequence: 3, ConnectedAt: time.Now()}
	if err = s.ApplyTunnelConnect(ctx, newTunnel, "", "tcp-source", "new-tcp-connect"); err != nil {
		t.Fatalf("new generation TCP registration rejected: %v", err)
	}
	got, err := s.ActiveTunnels(ctx, nil)
	if err != nil || len(got) != 2 {
		t.Fatalf("tunnels=%+v err=%v", got, err)
	}
	statuses := map[string]string{}
	for _, tunnel := range got {
		statuses[tunnel.ID] = tunnel.Status
	}
	if statuses[oldTunnel.ID] != "disconnecting" || statuses[newTunnel.ID] != "active" {
		t.Fatalf("statuses=%v", statuses)
	}
}

func TestMutationRollsBackWhenAuditInsertFails(t *testing.T) {
	ctx := context.Background()
	s := hardeningStore(t)
	uid, _ := seedIdentity(t, s, "alice", "fp", "old")
	if _, err := s.DB.Exec(`CREATE TRIGGER fail_audit BEFORE INSERT ON audit_logs BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	actor := uid
	if _, err := s.InsertSubdomainAtomic(ctx, uid, "new", AuditEntry{Actor: &actor, Target: &actor, Action: "subdomain.reserve", ResourceType: "subdomain"}); err == nil {
		t.Fatal("audit failure ignored")
	}
	var n int
	if err := s.DB.QueryRow(`SELECT count(*) FROM subdomains WHERE name='new'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("mutation committed: %d %v", n, err)
	}
}
func TestOutboxRetryAndIdempotentCompletion(t *testing.T) {
	ctx := context.Background()
	s := hardeningStore(t)
	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err = insertOutbox(ctx, tx, OutboxEvent{Kind: "pubkey.reconcile", DedupeKey: "same", Payload: map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	if err = insertOutbox(ctx, tx, OutboxEvent{Kind: "pubkey.reconcile", DedupeKey: "same", Payload: map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	items, err := s.PendingOutbox(ctx, 10)
	if err != nil || len(items) != 1 {
		t.Fatalf("dedupe: %d %v", len(items), err)
	}
	if err = s.RetryOutbox(ctx, items[0].ID, 1, "temporary"); err != nil {
		t.Fatal(err)
	}
	items, _ = s.PendingOutbox(ctx, 10)
	if len(items) != 0 {
		t.Fatal("retry backoff ignored")
	}
	if _, err = s.DB.Exec(`UPDATE outbox SET available_at=?`, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	items, _ = s.PendingOutbox(ctx, 10)
	if len(items) != 1 || items[0].Attempts != 1 {
		t.Fatal("retry state not durable")
	}
	if err = s.CompleteOutbox(ctx, items[0].ID); err != nil {
		t.Fatal(err)
	}
	if err = s.CompleteOutbox(ctx, items[0].ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("second completion mutated: %v", err)
	}
}
