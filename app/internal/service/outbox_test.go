package service

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"tunnel-control-plane/internal/integration"
	"tunnel-control-plane/internal/store"
)

type tunnelRecorder struct {
	fail        bool
	keys, users []int64
	hosts       []string
	ports       []int
}

func (t *tunnelRecorder) DisconnectKey(_ context.Context, id, generation int64) error {
	if t.fail {
		return errors.New("down")
	}
	t.keys = append(t.keys, id)
	return nil
}
func (t *tunnelRecorder) DisconnectUser(_ context.Context, id, generation int64) error {
	if t.fail {
		return errors.New("down")
	}
	t.users = append(t.users, id)
	return nil
}
func (t *tunnelRecorder) DisconnectPort(_ context.Context, port int, generation int64) error {
	if t.fail {
		return errors.New("down")
	}
	t.ports = append(t.ports, port)
	return nil
}
func (t *tunnelRecorder) DisconnectHost(_ context.Context, h string, generation int64) error {
	if t.fail {
		return errors.New("down")
	}
	t.hosts = append(t.hosts, h)
	return nil
}
func TestOutboxSnakeCaseIdentifiersAreDelivered(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "identifiers.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err = st.DB.Exec(`INSERT INTO outbox(kind,dedupe_key,payload) VALUES('tunnel.disconnect_key','key-test','{"key_id":42,"generation":7}')`); err != nil {
		t.Fatal(err)
	}
	recorder := &tunnelRecorder{}
	w := &OutboxWorker{Store: st, Keys: integration.PublicKeyWriter{Dir: filepath.Join(t.TempDir(), "keys")}, Tunnels: recorder}
	if err = w.ProcessOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(recorder.keys) != 1 || recorder.keys[0] != 42 {
		t.Fatalf("identifier not decoded: %v", recorder.keys)
	}
}

func TestTCPPortDisconnectOutboxIsDelivered(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "port-outbox.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err = st.DB.Exec(`INSERT INTO outbox(kind,dedupe_key,payload) VALUES('tunnel.disconnect_port','port-test','{"port":25565,"generation":7}')`); err != nil {
		t.Fatal(err)
	}
	recorder := &tunnelRecorder{}
	w := &OutboxWorker{Store: st, Keys: integration.PublicKeyWriter{Dir: filepath.Join(t.TempDir(), "keys")}, Tunnels: recorder}
	if err = w.ProcessOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(recorder.ports) != 1 || recorder.ports[0] != 25565 {
		t.Fatalf("port not delivered: %v", recorder.ports)
	}
}

func TestOutboxRetrySurvivesWorkerRestart(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "outbox.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	u, err := st.UpsertDiscordUser(ctx, "d", "u", "u", "", "", "user")
	if err != nil {
		t.Fatal(err)
	}
	id, err := st.InsertSubdomainAtomic(ctx, u.ID, "demo", store.AuditEntry{Actor: &u.ID, Target: &u.ID, Action: "reserve", ResourceType: "subdomain"})
	if err != nil {
		t.Fatal(err)
	}
	if err = st.DeleteSubdomainAtomic(ctx, id, "demo", store.AuditEntry{Actor: &u.ID, Target: &u.ID, Action: "release", ResourceType: "subdomain"}); err != nil {
		t.Fatal(err)
	}
	down := &tunnelRecorder{fail: true}
	w := &OutboxWorker{Store: st, Keys: integration.PublicKeyWriter{Dir: filepath.Join(t.TempDir(), "keys")}, Tunnels: down}
	if err = w.ProcessOnce(ctx); err == nil {
		t.Fatal("delivery failure ignored")
	}
	n, err := st.PendingOutboxCount(ctx)
	if err != nil || n != 1 {
		t.Fatalf("event lost: %d %v", n, err)
	}
	if _, err = st.DB.Exec(`UPDATE outbox SET available_at=?`, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	up := &tunnelRecorder{}
	restarted := &OutboxWorker{Store: st, Keys: w.Keys, Tunnels: up}
	if err = restarted.ProcessOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(up.hosts) != 1 || up.hosts[0] != "demo" {
		t.Fatalf("not delivered: %v", up.hosts)
	}
	if err = restarted.ProcessOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(up.hosts) != 1 {
		t.Fatalf("completed event repeated: %v", up.hosts)
	}
}
