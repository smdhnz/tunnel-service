package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"tunnel-control-plane/internal/store"
)

func internalTestServer(t *testing.T) (InternalServer, *store.Store, string, int64, int64) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "internal.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	u, err := st.UpsertDiscordUser(context.Background(), "d", "alice", "Alice", "", "", "user")
	if err != nil {
		t.Fatal(err)
	}
	r, err := st.DB.Exec(`INSERT INTO ssh_keys(user_id,name,public_key,fingerprint) VALUES(?,?,?,?)`, u.ID, "key", "ssh-ed25519 AAAA", "SHA256:key")
	if err != nil {
		t.Fatal(err)
	}
	kid, _ := r.LastInsertId()
	if _, err = st.DB.Exec(`INSERT INTO subdomains(user_id,name) VALUES(?,?)`, u.ID, "demo"); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(t.TempDir(), "token")
	secret := "01234567890123456789012345678901"
	if err = os.WriteFile(token, []byte(secret), 0600); err != nil {
		t.Fatal(err)
	}
	return InternalServer{Store: st, TokenFile: token, Domain: "example.test"}, st, secret, u.ID, kid
}
func internalRequest(t *testing.T, s InternalServer, secret, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	r.RemoteAddr = "127.0.0.1:12345"
	r.Header.Set("Authorization", "Bearer "+secret)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}
func TestInternalAuthorizationAndManualKeyDenied(t *testing.T) {
	s, st, secret, uid, kid := internalTestServer(t)
	w := internalRequest(t, s, secret, "/v1/authorize", bindAuthorization{Fingerprint: "SHA256:key", Protocol: "https", Hostname: "demo.example.test", Port: 443})
	if w.Code != 200 {
		t.Fatalf("valid=%d %s", w.Code, w.Body.String())
	}
	var v map[string]any
	json.Unmarshal(w.Body.Bytes(), &v)
	if int64(v["user_id"].(float64)) != uid || int64(v["key_id"].(float64)) != kid || v["hostname"] != "demo.example.test" {
		t.Fatalf("principal=%v", v)
	}
	for _, fp := range []string{"SHA256:manual", "SHA256:other"} {
		w = internalRequest(t, s, secret, "/v1/authorize", bindAuthorization{Fingerprint: fp, Protocol: "http", Hostname: "demo", Port: 80})
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s allowed: %d", fp, w.Code)
		}
	}
	if _, err := st.DB.Exec(`UPDATE ssh_keys SET enabled=0 WHERE id=?`, kid); err != nil {
		t.Fatal(err)
	}
	w = internalRequest(t, s, secret, "/v1/authorize", bindAuthorization{Fingerprint: "SHA256:key", Protocol: "http", Hostname: "demo", Port: 80})
	if w.Code != 403 {
		t.Fatal("disabled allowed")
	}
}
func TestInternalTokenAndTunnelLifecycle(t *testing.T) {
	s, st, secret, uid, kid := internalTestServer(t)
	r := httptest.NewRequest(http.MethodPost, "/v1/authorize", bytes.NewReader([]byte(`{}`)))
	r.RemoteAddr = "127.0.0.1:1"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("missing token=%d", w.Code)
	}
	e := tunnelEvent{EventID: "connect-1", SourceID: "source-1", ID: "tid", UserID: uid, KeyID: kid, Generation: 1, Sequence: 1, Protocol: "http", Hostname: "demo.example.test", Port: 80}
	w = internalRequest(t, s, secret, "/v1/tunnels/connect", e)
	if w.Code != 204 {
		t.Fatalf("connect=%d %s", w.Code, w.Body.String())
	}
	got, _ := st.ActiveTunnels(context.Background(), &uid)
	if len(got) != 1 || got[0].Hostname != "demo.example.test" {
		t.Fatalf("active=%+v", got)
	}
	w = internalRequest(t, s, secret, "/v1/tunnels/tid/disconnect", map[string]any{"event_id": "disconnect-1", "source_id": "source-1", "sequence": 2})
	if w.Code != 204 {
		t.Fatalf("disconnect=%d", w.Code)
	}
	got, _ = st.ActiveTunnels(context.Background(), &uid)
	if len(got) != 0 {
		t.Fatalf("still active=%d", len(got))
	}
}
