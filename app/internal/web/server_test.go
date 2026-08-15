package web

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tunnel-control-plane/internal/config"
	"tunnel-control-plane/internal/integration"
	"tunnel-control-plane/internal/service"
	"tunnel-control-plane/internal/store"
)

type noDNS struct{}

func (noDNS) HasExactRecord(context.Context, string) (bool, error) { return false, nil }
func testServer(t *testing.T) (*Server, *store.Store, string, string) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := config.Config{Addr: ":8080", TunnelDomain: "example.test", SSHHost: "ssh.example.test", SISHSSHPort: 2222, DiscordClientID: "id", DiscordClientSecret: "secret", DiscordRedirectURI: "http://localhost/auth/callback", SessionSecret: strings.Repeat("s", 32)}
	svc := &service.Service{Store: st, DNS: noDNS{}, Keys: integration.PublicKeyWriter{Dir: filepath.Join(t.TempDir(), "keys")}}
	s, err := New(cfg, st, svc, slog.New(slog.NewTextHandler(testWriter{t}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	u, err := st.UpsertDiscordUser(context.Background(), "normal", "normal", "Normal", "n@example.test", "", "user")
	if err != nil {
		t.Fatal(err)
	}
	token, csrf := "session-token", "csrf-token"
	if err = st.CreateSession(context.Background(), s.hash(token), u.ID, csrf, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return s, st, token, csrf
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimSpace(string(p)))
	return len(p), nil
}
func TestOAuthStateMismatch(t *testing.T) {
	s, _, _, _ := testServer(t)
	r := httptest.NewRequest(http.MethodGet, "/auth/callback?state=wrong&code=x", nil)
	r.AddCookie(&http.Cookie{Name: oauthCookie, Value: "different"})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("got %d", w.Code)
	}
}
func TestUnauthenticatedAccessRedirects(t *testing.T) {
	s, _, _, _ := testServer(t)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/keys", nil))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Fatalf("got %d %s", w.Code, w.Header().Get("Location"))
	}
}
func TestAdminDeniedForNormalUser(t *testing.T) {
	s, _, token, _ := testServer(t)
	r := httptest.NewRequest(http.MethodGet, "/admin", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("got %d", w.Code)
	}
}
func TestUnknownGetReturnsNotFound(t *testing.T) {
	s, _, token, _ := testServer(t)
	r := httptest.NewRequest(http.MethodGet, "/unknown", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("got %d", w.Code)
	}
}

func TestSecureOAuthCookieUsesHostPrefixAndRootPath(t *testing.T) {
	s, st, _, _ := testServer(t)
	s.cfg.CookieSecure = true
	if err := st.CreateOAuthState(context.Background(), sha("expired"), time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "https://control.example.test/auth/discord", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("got %d", w.Code)
	}
	var found bool
	for _, c := range w.Result().Cookies() {
		if c.Name == secureOAuthCookie && c.MaxAge > 0 {
			found = true
			if !c.Secure || !c.HttpOnly || c.Path != "/" || c.Domain != "" {
				t.Fatalf("invalid __Host cookie: %+v", c)
			}
		}
	}
	if !found {
		t.Fatal("secure OAuth state cookie missing")
	}
	var expired int
	if err := st.DB.QueryRow("SELECT count(*) FROM oauth_states WHERE state_hash=?", sha("expired")).Scan(&expired); err != nil || expired != 0 {
		t.Fatalf("expired OAuth state not cleaned: %d %v", expired, err)
	}
	session := s.authCookie(s.sessionCookieName(), "token", 60)
	if session.Name != secureSessionCookie || !session.Secure || session.Path != "/" || session.Domain != "" {
		t.Fatalf("invalid secure session cookie: %+v", session)
	}
}

func TestDesiredDisableEndpointIsRetrySafe(t *testing.T) {
	s, st, token, csrf := testServer(t)
	var uid int64
	if err := st.DB.QueryRow(`SELECT id FROM users WHERE discord_id='normal'`).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	r, err := st.DB.Exec(`INSERT INTO ssh_keys(user_id,name,public_key,fingerprint) VALUES(?,?,?,?)`, uid, "key", "ssh-ed25519 AAAA", "retry-fp")
	if err != nil {
		t.Fatal(err)
	}
	id, _ := r.LastInsertId()
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/keys/%d/disable", id), strings.NewReader("csrf_token="+csrf))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusSeeOther {
			t.Fatalf("retry %d status=%d", i, w.Code)
		}
	}
	var enabled int
	if err = st.DB.QueryRow(`SELECT enabled FROM ssh_keys WHERE id=?`, id).Scan(&enabled); err != nil || enabled != 0 {
		t.Fatalf("enabled=%d err=%v", enabled, err)
	}
	old := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/keys/%d/toggle", id), strings.NewReader("csrf_token="+csrf))
	old.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	old.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, old)
	if w.Code != http.StatusNotFound {
		t.Fatalf("legacy toggle status=%d", w.Code)
	}
}

func TestSessionAndCSRF(t *testing.T) {
	s, _, token, csrf := testServer(t)
	r := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader("csrf_token=bad"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("bad csrf got %d", w.Code)
	}
	r = httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader("csrf_token="+csrf))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("valid csrf got %d", w.Code)
	}
}
