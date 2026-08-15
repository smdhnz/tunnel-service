package store

import (
	"context"
	"database/sql"
	"errors"
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
func TestAuthorizeBindOwnershipEnabledAndActive(t *testing.T) {
	ctx := context.Background()
	s := hardeningStore(t)
	uid, kid := seedIdentity(t, s, "alice", "SHA256:alice", "mine")
	other, _ := seedIdentity(t, s, "bob", "SHA256:bob", "other")
	k, generation, err := s.AuthorizeBind(ctx, "SHA256:alice", "mine", "http", 80)
	if err != nil || generation < 1 || k.ID != kid || k.UserID != uid {
		t.Fatalf("valid rejected: %+v %v", k, err)
	}
	for name, fn := range map[string]func(){"manual": func() { _, _, err = s.AuthorizeBind(ctx, "SHA256:manual", "mine", "http", 80) }, "other owner": func() { _, _, err = s.AuthorizeBind(ctx, "SHA256:alice", "other", "https", 443) }, "invalid tcp": func() { _, _, err = s.AuthorizeBind(ctx, "SHA256:alice", "", "tcp", 0) }} {
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
