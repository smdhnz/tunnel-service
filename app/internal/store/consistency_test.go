package store

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"tunnel-control-plane/internal/model"
)

func TestAuthorizationGenerationClosesLateConnectRace(t *testing.T) {
	ctx := context.Background()
	s := hardeningStore(t)
	uid, kid := seedIdentity(t, s, "race", "race-fp", "race")
	_, generation, err := s.AuthorizeBind(ctx, "race-fp", "race", "http", 80)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SetKeyEnabledAtomic(ctx, kid, false, AuditEntry{Actor: &uid, Target: &uid, Action: "disable", ResourceType: "ssh_key"}); err != nil {
		t.Fatal(err)
	}
	late := model.ActiveTunnel{ID: "late", UserID: uid, SSHKeyID: kid, Protocol: "http", Hostname: "race.example.test", TCPPort: 80, Generation: generation, EventSequence: 1, ConnectedAt: time.Now()}
	if err = s.ApplyTunnelConnect(ctx, late, "race", "source-1", "late-connect"); err == nil {
		t.Fatal("late connect accepted after revocation")
	}
}

func TestDisconnectingRetainedUntilLifecycleConfirmation(t *testing.T) {
	ctx := context.Background()
	s := hardeningStore(t)
	uid, kid := seedIdentity(t, s, "state", "state-fp", "state")
	tunnel := model.ActiveTunnel{ID: "state-t", UserID: uid, SSHKeyID: kid, Protocol: "http", Hostname: "state.example.test", TCPPort: 80, Generation: 1, EventSequence: 1, ConnectedAt: time.Now()}
	if err := s.ApplyTunnelConnect(ctx, tunnel, "state", "source-1", "state-connect"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetKeyEnabledAtomic(ctx, kid, false, AuditEntry{Actor: &uid, Target: &uid, Action: "disable", ResourceType: "ssh_key"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ActiveTunnels(ctx, &uid)
	if err != nil || len(got) != 1 || got[0].Status != "disconnecting" {
		t.Fatalf("before confirmation: %+v %v", got, err)
	}
	if err = s.ApplyTunnelDisconnect(ctx, "state-t", "source-1", "state-disconnect", 2, time.Now()); err != nil {
		t.Fatal(err)
	}
	got, _ = s.ActiveTunnels(ctx, &uid)
	if len(got) != 0 {
		t.Fatalf("after confirmation: %+v", got)
	}
}

func TestSnapshotUnavailableMarksStaleAndRejectsOlderSequence(t *testing.T) {
	ctx := context.Background()
	s := hardeningStore(t)
	uid, kid := seedIdentity(t, s, "sync", "sync-fp", "sync")
	tunnel := model.ActiveTunnel{ID: "sync-t", UserID: uid, SSHKeyID: kid, Protocol: "http", Hostname: "sync.example.test", TCPPort: 80, Generation: 1, ConnectedAt: time.Now()}
	if err := s.ReconcileActiveSnapshot(ctx, model.TunnelSnapshot{SourceID: "source-1", Sequence: 4, Tunnels: []model.ActiveTunnel{tunnel}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkTunnelSyncUnavailable(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	got, _ := s.ActiveTunnels(ctx, nil)
	state, _ := s.TunnelSyncState(ctx)
	if state.Available || len(got) != 1 || got[0].Status != "stale" {
		t.Fatalf("state=%+v tunnels=%+v", state, got)
	}
	if err := s.ReconcileActiveSnapshot(ctx, model.TunnelSnapshot{SourceID: "source-1", Sequence: 3}, time.Now()); err == nil {
		t.Fatal("stale snapshot accepted")
	}
	if err := s.ReconcileActiveSnapshot(ctx, model.TunnelSnapshot{SourceID: "source-after-restart", Sequence: 1}, time.Now()); err != nil {
		t.Fatalf("new sish epoch rejected: %v", err)
	}
}

func TestKeyDeletionRetainsDisconnectingTunnelUntilConfirmation(t *testing.T) {
	ctx := context.Background()
	s := hardeningStore(t)
	uid, kid := seedIdentity(t, s, "delete", "delete-fp", "delete")
	tunnel := model.ActiveTunnel{ID: "delete-t", UserID: uid, SSHKeyID: kid, Protocol: "http", Hostname: "delete.example.test", TCPPort: 80, Generation: 1, EventSequence: 1, ConnectedAt: time.Now()}
	if err := s.ApplyTunnelConnect(ctx, tunnel, "delete", "source-1", "delete-connect"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteKeyAtomic(ctx, kid, uid, AuditEntry{Actor: &uid, Target: &uid, Action: "delete", ResourceType: "ssh_key"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ActiveTunnels(ctx, nil)
	if err != nil || len(got) != 1 || got[0].Status != "disconnecting" {
		t.Fatalf("tunnel lost before confirmation: %+v %v", got, err)
	}
}

func TestOutOfOrderConnectCannotReviveDisconnectedTunnel(t *testing.T) {
	ctx := context.Background()
	s := hardeningStore(t)
	uid, kid := seedIdentity(t, s, "order", "order-fp", "order")
	if err := s.ApplyTunnelDisconnect(ctx, "ordered", "source-1", "disconnect-first", 2, time.Now()); err != nil {
		t.Fatal(err)
	}
	late := model.ActiveTunnel{ID: "ordered", UserID: uid, SSHKeyID: kid, Protocol: "http", Hostname: "order.example.test", TCPPort: 80, Generation: 1, EventSequence: 1, ConnectedAt: time.Now()}
	if err := s.ApplyTunnelConnect(ctx, late, "order", "source-1", "connect-late"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.ActiveTunnels(ctx, nil)
	if len(got) != 0 {
		t.Fatalf("late connect revived tunnel: %+v", got)
	}
}

func TestRetiredTunnelSourceCannotReplayEventsOrSnapshots(t *testing.T) {
	ctx := context.Background()
	s := hardeningStore(t)
	uid, kid := seedIdentity(t, s, "epoch", "epoch-fp", "epoch")
	oldTunnel := model.ActiveTunnel{ID: "old", UserID: uid, SSHKeyID: kid, Protocol: "http", Hostname: "epoch.example.test", TCPPort: 80, Generation: 1, EventSequence: 1, ConnectedAt: time.Now()}
	if err := s.ReconcileActiveSnapshot(ctx, model.TunnelSnapshot{SourceID: "old-source", Sequence: 1, Tunnels: []model.ActiveTunnel{oldTunnel}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.ReconcileActiveSnapshot(ctx, model.TunnelSnapshot{SourceID: "new-source", Sequence: 1}, time.Now()); err != nil {
		t.Fatal(err)
	}
	oldTunnel.EventSequence = 99
	if err := s.ApplyTunnelConnect(ctx, oldTunnel, "epoch", "old-source", "late-old-connect"); err == nil {
		t.Fatal("retired source event accepted")
	}
	if err := s.ReconcileActiveSnapshot(ctx, model.TunnelSnapshot{SourceID: "old-source", Sequence: 100, Tunnels: []model.ActiveTunnel{oldTunnel}}, time.Now()); err == nil {
		t.Fatal("retired source snapshot accepted")
	}
}

func TestTelemetryBatchIdempotentAndAtomic(t *testing.T) {
	ctx := context.Background()
	s := hardeningStore(t)
	events := map[string]int64{"unknown_host": 7, "rate_limited": 2}
	if err := s.AddSecurityTelemetryBatch(ctx, "batch-1", events); err != nil {
		t.Fatal(err)
	}
	if err := s.AddSecurityTelemetryBatch(ctx, "batch-1", events); err != nil {
		t.Fatal(err)
	}
	var total int
	if err := s.DB.QueryRow(`SELECT sum(count) FROM security_telemetry`).Scan(&total); err != nil || total != 9 {
		t.Fatalf("total=%d err=%v", total, err)
	}
}

func TestLoginSessionAndAuditRollbackTogether(t *testing.T) {
	ctx := context.Background()
	s := hardeningStore(t)
	if _, err := s.DB.Exec(`CREATE TRIGGER fail_login_audit BEFORE INSERT ON audit_logs WHEN NEW.action='login' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`); err != nil {
		t.Fatal(err)
	}
	_, err := s.LoginDiscordAtomic(ctx, "new-login", "u", "U", "", "", "user", "hash", "csrf", time.Now().Add(time.Hour), "127.0.0.1")
	if err == nil {
		t.Fatal("audit failure ignored")
	}
	var sessions, users int
	_ = s.DB.QueryRow(`SELECT count(*) FROM sessions`).Scan(&sessions)
	_ = s.DB.QueryRow(`SELECT count(*) FROM users WHERE discord_id='new-login'`).Scan(&users)
	if sessions != 0 || users != 0 {
		t.Fatalf("partial login users=%d sessions=%d", users, sessions)
	}
}

func TestSuspensionBlocksConcurrentClassMutations(t *testing.T) {
	ctx := context.Background()
	s := hardeningStore(t)
	u, err := s.UpsertDiscordUser(ctx, "suspend-race", "u", "U", "", "", "user")
	if err != nil {
		t.Fatal(err)
	}
	actor := u.ID
	if err = s.SetUserStatusAtomic(ctx, u.ID, "suspended", AuditEntry{Actor: &actor, Target: &actor, Action: "suspend", ResourceType: "user"}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.InsertSubdomainAtomic(ctx, u.ID, "blocked", AuditEntry{Actor: &actor, Target: &actor, Action: "reserve", ResourceType: "subdomain"}); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("subdomain mutation allowed: %v", err)
	}
	if _, err = s.LoginDiscordAtomic(ctx, "suspend-race", "u", "U", "", "", "user", "session", "csrf", time.Now().Add(time.Hour), "127.0.0.1"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("session mutation allowed: %v", err)
	}
	var sessions, domains int
	_ = s.DB.QueryRow(`SELECT count(*) FROM sessions WHERE user_id=?`, u.ID).Scan(&sessions)
	_ = s.DB.QueryRow(`SELECT count(*) FROM subdomains WHERE user_id=?`, u.ID).Scan(&domains)
	if sessions != 0 || domains != 0 {
		t.Fatalf("sessions=%d domains=%d", sessions, domains)
	}
}

func TestDesiredStateMutationIsIdempotent(t *testing.T) {
	ctx := context.Background()
	s := hardeningStore(t)
	uid, kid := seedIdentity(t, s, "desired", "desired-fp", "")
	a := AuditEntry{Actor: &uid, Target: &uid, Action: "disable", ResourceType: "ssh_key"}
	if err := s.SetKeyEnabledAtomic(ctx, kid, false, a); err != nil {
		t.Fatal(err)
	}
	if err := s.SetKeyEnabledAtomic(ctx, kid, false, a); err != nil {
		t.Fatal(err)
	}
	var enabled int
	if err := s.DB.QueryRow(`SELECT enabled FROM ssh_keys WHERE id=?`, kid).Scan(&enabled); err != nil || enabled != 0 {
		t.Fatalf("enabled=%d err=%v", enabled, err)
	}
	var audits int
	_ = s.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE action='disable'`).Scan(&audits)
	if audits != 1 {
		t.Fatalf("duplicate audit=%d", audits)
	}
	if !errors.Is(func() error { _, _, e := s.AuthorizeBind(ctx, "desired-fp", "", "tcp", 80); return e }(), sql.ErrNoRows) {
		t.Fatal("disabled key authorized")
	}
}
