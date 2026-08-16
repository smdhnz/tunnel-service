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
func TestDashboardExplainsTCPUsageWithConfiguredSSHHost(t *testing.T) {
	s, _, token, _ := testServer(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "MinecraftなどのTCPサービス") || !strings.Contains(body, "ssh.example.test:予約ポート") || !strings.Contains(body, "先に「TCPポート」でポートを予約") || !strings.Contains(body, "-R PUBLIC_PORT:127.0.0.1:LOCAL_PORT ssh.example.test") {
		t.Fatalf("status=%d body=%s", w.Code, body)
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

func TestKeysPageRendersRegisteredKey(t *testing.T) {
	s, st, token, _ := testServer(t)
	var uid int64
	if err := st.DB.QueryRow(`SELECT id FROM users WHERE discord_id='normal'`).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.Exec(`INSERT INTO ssh_keys(user_id,name,public_key,fingerprint) VALUES(?,?,?,?)`, uid, "端末", "ssh-ed25519 AAAA", "SHA256:test"); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/keys", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "SHA256:test") || !strings.Contains(body, "</html>") {
		t.Fatalf("status=%d complete=%t fingerprint=%t", w.Code, strings.Contains(body, "</html>"), strings.Contains(body, "SHA256:test"))
	}
}

func TestTCPPortUserAndAdminRoutes(t *testing.T) {
	s, st, token, csrf := testServer(t)
	post := func(path, form string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	w := post("/tcp-ports", "csrf_token="+csrf+"&port=25565")
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/tcp-ports?") {
		t.Fatalf("reserve status=%d location=%s", w.Code, w.Header().Get("Location"))
	}
	r := httptest.NewRequest(http.MethodGet, "/tcp-ports", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "25565") || !strings.Contains(body, "/tcp-ports/") || !strings.Contains(body, `min="10000"`) || !strings.Contains(body, "10000〜65535") {
		t.Fatalf("user page status=%d body=%s", w.Code, body)
	}
	var uid, id int64
	if err := st.DB.QueryRow(`SELECT id FROM users WHERE discord_id='normal'`).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	if err := st.DB.QueryRow(`SELECT id FROM tcp_ports WHERE port=25565`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB.Exec(`UPDATE users SET role='admin' WHERE id=?`, uid); err != nil {
		t.Fatal(err)
	}
	r = httptest.NewRequest(http.MethodGet, "/admin/tcp-ports", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "/admin/tcp-ports/") {
		t.Fatalf("admin page status=%d", w.Code)
	}
	w = post(fmt.Sprintf("/admin/tcp-ports/%d/release", id), "csrf_token="+csrf)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("force release status=%d", w.Code)
	}
	var count int
	if err := st.DB.QueryRow(`SELECT count(*) FROM tcp_ports WHERE id=?`, id).Scan(&count); err != nil || count != 0 {
		t.Fatalf("port count=%d err=%v", count, err)
	}
}

func TestAdminPaginationParameters(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/admin/tunnels?tunnel_page=2&tunnel_per_page=30&security_page=3&security_per_page=50", nil)
	page, size, offset := requestedPage(r, "tunnel_page", "tunnel_per_page")
	if page != 2 || size != 30 || offset != 30 {
		t.Fatalf("page=%d size=%d offset=%d", page, size, offset)
	}
	p := pagination(r, "tunnel_page", "tunnel_per_page", page, size, true)
	if p.PreviousURL != "/admin/tunnels?security_page=3&security_per_page=50&tunnel_per_page=30" || p.NextURL != "/admin/tunnels?security_page=3&security_per_page=50&tunnel_page=3&tunnel_per_page=30" {
		t.Fatalf("previous=%q next=%q", p.PreviousURL, p.NextURL)
	}
	if len(p.PageSizes) != 4 || !p.PageSizes[1].Selected {
		t.Fatalf("page sizes=%+v", p.PageSizes)
	}

	r = httptest.NewRequest(http.MethodGet, "/admin/users?page=invalid&per_page=25", nil)
	page, size, offset = requestedPage(r, "page", "per_page")
	if page != 1 || size != 10 || offset != 0 {
		t.Fatalf("invalid fallback: page=%d size=%d offset=%d", page, size, offset)
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
