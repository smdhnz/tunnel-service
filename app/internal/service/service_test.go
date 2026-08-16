package service

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tunnel-control-plane/internal/model"

	"golang.org/x/crypto/ssh"
	"tunnel-control-plane/internal/integration"
	"tunnel-control-plane/internal/store"
)

type dnsMock struct {
	conflict bool
	err      error
}

func (d dnsMock) HasExactRecord(context.Context, string) (bool, error) { return d.conflict, d.err }
func testService(t *testing.T, dns dnsMock) (*Service, *store.Store, int64, int64) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	u1, err := st.UpsertDiscordUser(context.Background(), "d1", "alice", "Alice", "a@example.test", "", "user")
	if err != nil {
		t.Fatal(err)
	}
	u2, err := st.UpsertDiscordUser(context.Background(), "d2", "bob", "Bob", "b@example.test", "", "user")
	if err != nil {
		t.Fatal(err)
	}
	return &Service{Store: st, DNS: dns, Keys: integration.PublicKeyWriter{Dir: filepath.Join(t.TempDir(), "pubkeys")}}, st, u1.ID, u2.ID
}
func validKey(t *testing.T, seed byte) string {
	t.Helper()
	raw := make([]byte, ed25519.SeedSize)
	for i := range raw {
		raw[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(raw)
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " test@example"
}
func TestValidatePublicKey(t *testing.T) {
	valid := validKey(t, 1)
	if _, fp, err := ValidatePublicKey(valid); err != nil || !strings.HasPrefix(fp, "SHA256:") {
		t.Fatalf("valid key rejected: %v %q", err, fp)
	}
	if _, _, err := ValidatePublicKey("not-a-key"); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("want invalid, got %v", err)
	}
	if _, _, err := ValidatePublicKey(strings.Repeat("x", MaxPublicKeyBytes+1)); !errors.Is(err, ErrKeyTooLarge) {
		t.Fatalf("want oversized, got %v", err)
	}
}
func TestKeyDuplicateAndOwnership(t *testing.T) {
	svc, st, u1, u2 := testService(t, dnsMock{})
	id, err := svc.AddKey(context.Background(), u1, "laptop", validKey(t, 2), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.AddKey(context.Background(), u2, "copy", validKey(t, 2), ""); !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("want duplicate, got %v", err)
	}
	if err = svc.DeleteKey(context.Background(), u2, false, id, ""); !errors.Is(err, ErrForbidden) {
		t.Fatalf("cross-user delete allowed: %v", err)
	}
	k, _ := st.Key(context.Background(), id)
	if !k.Enabled {
		t.Fatal("key unexpectedly disabled")
	}
	if _, err = os.Stat(svc.Keys.(integration.PublicKeyWriter).Dir + "/" + "control-plane-1-1.pub"); err != nil {
		t.Fatalf("pubkey not synced: %v", err)
	}
}

type failingKeyStore struct {
	delegate  PublicKeyStore
	removeErr error
}

func (f failingKeyStore) Write(k model.SSHKey) error          { return f.delegate.Write(k) }
func (f failingKeyStore) Reconcile(keys []model.SSHKey) error { return f.delegate.Reconcile(keys) }
func (f failingKeyStore) Remove(userID, keyID int64) error {
	if f.removeErr != nil {
		return f.removeErr
	}
	return f.delegate.Remove(userID, keyID)
}

func TestKeyRevocationIOFailureDoesNotCommitDBMutation(t *testing.T) {
	svc, st, user, _ := testService(t, dnsMock{})
	id, err := svc.AddKey(context.Background(), user, "laptop", validKey(t, 8), "")
	if err != nil {
		t.Fatal(err)
	}
	svc.Keys = failingKeyStore{delegate: svc.Keys, removeErr: errors.New("disk unavailable")}
	if err = svc.SetKeyEnabled(context.Background(), user, false, id, false, ""); err == nil {
		t.Fatal("filesystem failure ignored")
	}
	k, err := st.Key(context.Background(), id)
	if err != nil || !k.Enabled {
		t.Fatalf("DB changed before revocation succeeded: enabled=%v err=%v", k.Enabled, err)
	}
}

type trackingKeyStore struct {
	mu          sync.Mutex
	active, max int
}

func (t *trackingKeyStore) enter() {
	t.mu.Lock()
	t.active++
	if t.active > t.max {
		t.max = t.active
	}
	t.mu.Unlock()
	time.Sleep(5 * time.Millisecond)
	t.mu.Lock()
	t.active--
	t.mu.Unlock()
}
func (t *trackingKeyStore) Write(model.SSHKey) error       { t.enter(); return nil }
func (t *trackingKeyStore) Remove(int64, int64) error      { t.enter(); return nil }
func (t *trackingKeyStore) Reconcile([]model.SSHKey) error { t.enter(); return nil }

func TestKeyFileChangesAreSerialized(t *testing.T) {
	svc, _, user, _ := testService(t, dnsMock{})
	tracker := &trackingKeyStore{}
	svc.Keys = tracker
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 1; i <= 8; i++ {
		wg.Add(1)
		go func(seed byte) {
			defer wg.Done()
			_, err := svc.AddKey(context.Background(), user, "key", validKey(t, seed), "")
			errs <- err
		}(byte(i + 20))
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if tracker.max != 1 {
		t.Fatalf("concurrent key writes: max=%d", tracker.max)
	}
}

func TestNormalizeSubdomain(t *testing.T) {
	cases := map[string]string{" Foo ": "foo", "a-b": "a-b"}
	for in, want := range cases {
		got, err := NormalizeSubdomain(in)
		if err != nil || got != want {
			t.Fatalf("%q => %q %v", in, got, err)
		}
	}
	for _, in := range []string{"www", "tunnel", "bad_name", "-bad", "bad-", ""} {
		if _, err := NormalizeSubdomain(in); err == nil {
			t.Fatalf("%q accepted", in)
		}
	}
}
func TestTunnelSubdomainCanOnlyBeReservedByAdmin(t *testing.T) {
	ctx := context.Background()
	svc, st, userID, _ := testService(t, dnsMock{})
	if _, err := svc.ReserveSubdomain(ctx, userID, "tunnel", ""); !errors.Is(err, ErrReservedSubdomain) {
		t.Fatalf("user reserved tunnel: %v", err)
	}
	admin, err := st.UpsertDiscordUser(ctx, "admin", "admin", "Admin", "admin@example.test", "", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.ReserveSubdomain(ctx, admin.ID, "tunnel", ""); err != nil {
		t.Fatalf("admin could not reserve tunnel: %v", err)
	}
}

func TestSubdomainReservationChecks(t *testing.T) {
	ctx := context.Background()
	svc, _, u1, u2 := testService(t, dnsMock{})
	id, err := svc.ReserveSubdomain(ctx, u1, " Demo ", "")
	if err != nil || id == 0 {
		t.Fatalf("reserve: %v", err)
	}
	if _, err = svc.ReserveSubdomain(ctx, u2, "demo", ""); !errors.Is(err, ErrDuplicateSubdomain) {
		t.Fatalf("duplicate: %v", err)
	}
	if err = svc.ReleaseSubdomain(ctx, u2, false, id, ""); !errors.Is(err, ErrForbidden) {
		t.Fatalf("cross release: %v", err)
	}
	svc.DNS = dnsMock{conflict: true}
	if _, err = svc.ReserveSubdomain(ctx, u1, "vercel", ""); !errors.Is(err, ErrDNSConflict) {
		t.Fatalf("conflict: %v", err)
	}
	svc.DNS = dnsMock{err: errors.New("offline")}
	if _, err = svc.ReserveSubdomain(ctx, u1, "offline", ""); !errors.Is(err, ErrDNSUnavailable) {
		t.Fatalf("fail-open: %v", err)
	}
}
func TestAdminSuspendUnsuspendRevokeAndForceRelease(t *testing.T) {
	ctx := context.Background()
	svc, st, admin, user := testService(t, dnsMock{})
	if _, err := st.DB.Exec("UPDATE users SET role='admin' WHERE id=?", admin); err != nil {
		t.Fatal(err)
	}
	keyID, err := svc.AddKey(ctx, user, "phone", validKey(t, 3), "")
	if err != nil {
		t.Fatal(err)
	}
	domainID, err := svc.ReserveSubdomain(ctx, user, "sample", "")
	if err != nil {
		t.Fatal(err)
	}
	if err = svc.SetUserSuspended(ctx, admin, user, true, ""); err != nil {
		t.Fatal(err)
	}
	u, _ := st.UserByID(ctx, user)
	if u.Status != "suspended" {
		t.Fatal("not suspended")
	}
	if keys, err := st.AuthorizedKeys(ctx); err != nil || len(keys) != 0 {
		t.Fatalf("suspended key authorized: %v %d", err, len(keys))
	}
	if err = svc.SetUserSuspended(ctx, admin, user, false, ""); err != nil {
		t.Fatal(err)
	}
	if err = svc.DeleteKey(ctx, admin, true, keyID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err = st.Key(ctx, keyID); !IsNotFound(err) {
		t.Fatalf("key not revoked: %v", err)
	}
	if err = svc.ReleaseSubdomain(ctx, admin, true, domainID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err = st.Subdomain(ctx, domainID); !IsNotFound(err) {
		t.Fatalf("domain not released: %v", err)
	}
}
