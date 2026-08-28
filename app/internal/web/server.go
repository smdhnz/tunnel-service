package web

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"tunnel-control-plane/internal/config"
	"tunnel-control-plane/internal/integration"
	"tunnel-control-plane/internal/model"
	"tunnel-control-plane/internal/service"
	"tunnel-control-plane/internal/store"
)

// The Vite build writes hashed-free assets to static/dist before the Go binary is built.
// static/index.html is kept as source so Go unit tests do not require Node.
//
//go:embed static
var assets embed.FS

type Server struct {
	cfg                                     config.Config
	store                                   *store.Store
	svc                                     *service.Service
	mux                                     *http.ServeMux
	client                                  *http.Client
	logger                                  *slog.Logger
	generalLimit, loginLimit, mutationLimit *rateLimiter
}
type ctxKey int

const userKey ctxKey = 1
const sessionCookie = "tunnel_session"
const oauthCookie = "oauth_state"
const secureSessionCookie = "__Host-tunnel_session"
const secureOAuthCookie = "__Host-oauth_state"

const defaultAdminPageSize = 10

type Pagination struct {
	Page                 int
	PreviousURL, NextURL string
}
type Page struct {
	Title, Page, CSRF, Flash, Error, TunnelDomain, SSHHost, ConnectCommand string
	SSHPort                                                                int
	User                                                                   *model.User
	Keys                                                                   []model.SSHKey
	Subdomains                                                             []model.Subdomain
	TCPPorts                                                               []model.TCPPort
	Users                                                                  []model.User
	Audit                                                                  []model.AuditLog
	ActiveTunnels                                                          []model.ActiveTunnel
	SecurityMetrics                                                        []model.SecurityMetric
	Stats                                                                  model.Stats
	Pagination                                                             Pagination
	ActiveTunnelAvailable                                                  bool
}

func New(cfg config.Config, st *store.Store, svc *service.Service, logger *slog.Logger) (*Server, error) {
	s := &Server{cfg: cfg, store: st, svc: svc, mux: http.NewServeMux(), client: &http.Client{Timeout: 10 * time.Second}, logger: logger,
		generalLimit: newRateLimiter(120, 2, 5*time.Minute), loginLimit: newRateLimiter(10, 10.0/60, 15*time.Minute), mutationLimit: newRateLimiter(30, 0.5, 10*time.Minute)}
	s.routes()
	return s, nil
}
func (s *Server) Handler() http.Handler { return s.security(s.hostCheck(s.rateLimit(s.mux))) }
func (s *Server) routes() {
	s.mux.Handle("GET /static/", http.FileServer(http.FS(assets)))
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("ok\n"))
	})
	s.mux.HandleFunc("GET /login", s.loginPage)
	s.mux.HandleFunc("GET /auth/discord", s.oauthStart)
	s.mux.HandleFunc("GET /auth/callback", s.oauthCallback)
	s.mux.Handle("GET /api/page", s.auth(http.HandlerFunc(s.apiPage)))
	s.mux.Handle("POST /api/action", s.auth(s.csrf(http.HandlerFunc(s.apiAction))))

	for _, path := range []string{"/{$}", "/keys", "/subdomains", "/tcp-ports", "/tunnels"} {
		s.mux.Handle("GET "+path, s.auth(http.HandlerFunc(s.spaPage)))
	}
	for _, path := range []string{"/admin", "/admin/users", "/admin/keys", "/admin/subdomains", "/admin/tcp-ports", "/admin/tunnels", "/admin/security"} {
		s.mux.Handle("GET "+path, s.auth(s.admin(http.HandlerFunc(s.spaPage))))
	}

	s.mux.Handle("POST /logout", s.auth(s.csrf(http.HandlerFunc(s.logout))))
	s.mux.Handle("POST /keys", s.auth(s.csrf(http.HandlerFunc(s.keyAdd))))
	s.mux.Handle("POST /keys/{id}/enable", s.auth(s.csrf(http.HandlerFunc(s.keyEnable))))
	s.mux.Handle("POST /keys/{id}/disable", s.auth(s.csrf(http.HandlerFunc(s.keyDisable))))
	s.mux.Handle("POST /keys/{id}/delete", s.auth(s.csrf(http.HandlerFunc(s.keyDelete))))
	s.mux.Handle("POST /subdomains", s.auth(s.csrf(http.HandlerFunc(s.subdomainReserve))))
	s.mux.Handle("POST /subdomains/{id}/release", s.auth(s.csrf(http.HandlerFunc(s.subdomainRelease))))
	s.mux.Handle("POST /tcp-ports", s.auth(s.csrf(http.HandlerFunc(s.tcpPortReserve))))
	s.mux.Handle("POST /tcp-ports/{id}/release", s.auth(s.csrf(http.HandlerFunc(s.tcpPortRelease))))
	s.mux.Handle("POST /admin/users/{id}/suspend", s.auth(s.admin(s.csrf(http.HandlerFunc(s.adminUserSuspend)))))
	s.mux.Handle("POST /admin/users/{id}/unsuspend", s.auth(s.admin(s.csrf(http.HandlerFunc(s.adminUserUnsuspend)))))
	s.mux.Handle("POST /admin/keys/{id}/enable", s.auth(s.admin(s.csrf(http.HandlerFunc(s.adminKeyEnable)))))
	s.mux.Handle("POST /admin/keys/{id}/disable", s.auth(s.admin(s.csrf(http.HandlerFunc(s.adminKeyDisable)))))
	s.mux.Handle("POST /admin/keys/{id}/revoke", s.auth(s.admin(s.csrf(http.HandlerFunc(s.adminKeyRevoke)))))
	s.mux.Handle("POST /admin/subdomains/{id}/release", s.auth(s.admin(s.csrf(http.HandlerFunc(s.adminSubdomainRelease)))))
	s.mux.Handle("POST /admin/tcp-ports/{id}/release", s.auth(s.admin(s.csrf(http.HandlerFunc(s.adminTCPPortRelease)))))
}
func (s *Server) security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' https://cdn.discordapp.com data:; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		}
		next.ServeHTTP(w, r)
	})
}
func (s *Server) hostCheck(next http.Handler) http.Handler {
	if s.cfg.PublicHost == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, e := net.SplitHostPort(host); e == nil {
			host = h
		}
		if !strings.EqualFold(strings.TrimSuffix(host, "."), strings.TrimSuffix(s.cfg.PublicHost, ".")) {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(s.sessionCookieName())
		if err != nil {
			s.redirectLogin(w, r)
			return
		}
		u, csrf, err := s.store.SessionUser(r.Context(), s.hash(c.Value), time.Now())
		if err != nil || u.Status != "active" {
			s.clearCookie(w, s.sessionCookieName())
			s.redirectLogin(w, r)
			return
		}
		ctx := context.WithValue(r.Context(), userKey, struct {
			User *model.User
			CSRF string
		}{u, csrf})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
func (s *Server) admin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if current(r).User.Role != "admin" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		got := r.Form.Get("csrf_token")
		want := current(r).CSRF
		if len(got) != len(want) || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			http.Error(w, "CSRF validation failed", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func current(r *http.Request) struct {
	User *model.User
	CSRF string
} {
	return r.Context().Value(userKey).(struct {
		User *model.User
		CSRF string
	})
}
func (s *Server) redirectLogin(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie(s.sessionCookieName()); err == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.spaPage(w, r)
}

func (s *Server) spaPage(w http.ResponseWriter, _ *http.Request) {
	body, err := assets.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "Frontend is not available", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(body)
}

// apiAction keeps all mutation routing and authorization in Go while allowing
// the SPA to update without a document navigation.
func (s *Server) apiAction(w http.ResponseWriter, r *http.Request) {
	action := r.Form.Get("_action")
	parts := strings.Split(strings.Trim(action, "/"), "/")
	if action == "/logout" {
		s.logout(w, r)
		return
	}
	if action == "/keys" {
		s.keyAdd(w, r)
		return
	}
	if action == "/subdomains" {
		s.subdomainReserve(w, r)
		return
	}
	if action == "/tcp-ports" {
		s.tcpPortReserve(w, r)
		return
	}
	if len(parts) == 3 {
		r.SetPathValue("id", parts[1])
		switch {
		case parts[0] == "keys" && parts[2] == "enable":
			s.keyEnable(w, r)
		case parts[0] == "keys" && parts[2] == "disable":
			s.keyDisable(w, r)
		case parts[0] == "keys" && parts[2] == "delete":
			s.keyDelete(w, r)
		case parts[0] == "subdomains" && parts[2] == "release":
			s.subdomainRelease(w, r)
		case parts[0] == "tcp-ports" && parts[2] == "release":
			s.tcpPortRelease(w, r)
		default:
			http.NotFound(w, r)
		}
		return
	}
	if len(parts) == 4 && parts[0] == "admin" {
		if current(r).User.Role != "admin" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		r.SetPathValue("id", parts[2])
		switch {
		case parts[1] == "users" && parts[3] == "suspend":
			s.adminUserSuspend(w, r)
		case parts[1] == "users" && parts[3] == "unsuspend":
			s.adminUserUnsuspend(w, r)
		case parts[1] == "keys" && parts[3] == "enable":
			s.adminKeyEnable(w, r)
		case parts[1] == "keys" && parts[3] == "disable":
			s.adminKeyDisable(w, r)
		case parts[1] == "keys" && parts[3] == "revoke":
			s.adminKeyRevoke(w, r)
		case parts[1] == "subdomains" && parts[3] == "release":
			s.adminSubdomainRelease(w, r)
		case parts[1] == "tcp-ports" && parts[3] == "release":
			s.adminTCPPortRelease(w, r)
		default:
			http.NotFound(w, r)
		}
		return
	}
	http.NotFound(w, r)
}

// apiPage reuses the authenticated page loaders. The path is a relative URL so
// React Router can preserve each screen's existing URL and query pagination.
func (s *Server) apiPage(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("path")
	u, err := url.ParseRequestURI(target)
	if err != nil || u.IsAbs() || u.Host != "" || !strings.HasPrefix(u.Path, "/") {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	request := r.Clone(r.Context())
	request.URL = u
	request.RequestURI = target
	switch u.Path {
	case "/":
		s.dashboard(w, request)
	case "/keys":
		s.keysPage(w, request)
	case "/subdomains":
		s.subdomainsPage(w, request)
	case "/tcp-ports":
		s.tcpPortsPage(w, request)
	case "/tunnels":
		s.tunnelsPage(w, request)
	case "/admin", "/admin/users", "/admin/keys", "/admin/subdomains", "/admin/tcp-ports", "/admin/tunnels", "/admin/security":
		if current(r).User.Role != "admin" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		switch u.Path {
		case "/admin":
			s.adminHome(w, request)
		case "/admin/users":
			s.adminUsers(w, request)
		case "/admin/keys":
			s.adminKeys(w, request)
		case "/admin/subdomains":
			s.adminSubdomains(w, request)
		case "/admin/tcp-ports":
			s.adminTCPPorts(w, request)
		case "/admin/tunnels":
			s.adminTunnels(w, request)
		case "/admin/security":
			s.adminSecurity(w, request)
		}
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) oauthStart(w http.ResponseWriter, r *http.Request) {
	if err := s.store.CleanupAuth(r.Context(), time.Now()); err != nil {
		s.internal(w, r, err)
		return
	}
	// Starting a new login invalidates any prior session and OAuth attempt.
	// The callback always creates a fresh random session token.
	if c, err := r.Cookie(s.sessionCookieName()); err == nil {
		if err = s.store.DeleteSession(r.Context(), s.hash(c.Value)); err != nil {
			s.internal(w, r, err)
			return
		}
	}
	s.clearCookie(w, s.sessionCookieName())
	s.clearCookie(w, s.oauthCookieName())
	state := randomToken(32)
	if err := s.store.CreateOAuthState(r.Context(), sha(state), time.Now().Add(10*time.Minute)); err != nil {
		s.internal(w, r, err)
		return
	}
	http.SetCookie(w, s.authCookie(s.oauthCookieName(), state, 600))
	q := url.Values{"client_id": {s.cfg.DiscordClientID}, "redirect_uri": {s.cfg.DiscordRedirectURI}, "response_type": {"code"}, "scope": {"identify email"}, "state": {state}}
	http.Redirect(w, r, "https://discord.com/oauth2/authorize?"+q.Encode(), http.StatusFound)
}
func (s *Server) oauthCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	cookie, err := r.Cookie(s.oauthCookieName())
	if err != nil || state == "" || len(state) != len(cookie.Value) || subtle.ConstantTimeCompare([]byte(state), []byte(cookie.Value)) != 1 {
		http.Error(w, "OAuth state validation failed", http.StatusBadRequest)
		return
	}
	ok, err := s.store.ConsumeOAuthState(r.Context(), sha(state), time.Now())
	s.clearCookie(w, s.oauthCookieName())
	if err != nil || !ok {
		http.Error(w, "OAuth state validation failed", http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "OAuth authorization failed", http.StatusBadRequest)
		return
	}
	token, err := s.discordToken(r.Context(), code)
	if err != nil {
		s.logger.Warn("Discord OAuth token exchange failed")
		http.Error(w, "Authentication failed", http.StatusBadGateway)
		return
	}
	du, err := s.discordUser(r.Context(), token)
	if err != nil {
		s.logger.Warn("Discord user lookup failed")
		http.Error(w, "Authentication failed", http.StatusBadGateway)
		return
	}
	role := "user"
	if s.cfg.AdminDiscordIDs[du.ID] {
		role = "admin"
	}
	avatar := ""
	if du.Avatar != "" {
		avatar = "https://cdn.discordapp.com/avatars/" + url.PathEscape(du.ID) + "/" + url.PathEscape(du.Avatar) + ".png"
	}
	display := du.GlobalName
	if display == "" {
		display = du.Username
	}
	session := randomToken(32)
	csrf := randomToken(24)
	_, err = s.store.LoginDiscordAtomic(r.Context(), du.ID, du.Username, display, du.Email, avatar, role, s.hash(session), csrf, time.Now().Add(7*24*time.Hour), sourceIP(r))
	if service.IsNotFound(err) {
		http.Error(w, "Account suspended", http.StatusForbidden)
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	http.SetCookie(w, s.authCookie(s.sessionCookieName(), session, 7*24*3600))
	http.Redirect(w, r, "/?flash=login", http.StatusSeeOther)
}

type discordUser struct {
	ID         string `json:"id"`
	Username   string `json:"username"`
	GlobalName string `json:"global_name"`
	Email      string `json:"email"`
	Avatar     string `json:"avatar"`
}

func (s *Server) discordToken(ctx context.Context, code string) (string, error) {
	form := url.Values{"client_id": {s.cfg.DiscordClientID}, "client_secret": {s.cfg.DiscordClientSecret}, "grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {s.cfg.DiscordRedirectURI}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://discord.com/api/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", errors.New("token status")
	}
	var v struct {
		AccessToken string `json:"access_token"`
	}
	if err = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&v); err != nil || v.AccessToken == "" {
		return "", errors.New("invalid token response")
	}
	return v.AccessToken, nil
}
func (s *Server) discordUser(ctx context.Context, token string) (discordUser, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://discord.com/api/users/@me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := s.client.Do(req)
	if err != nil {
		return discordUser{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return discordUser{}, errors.New("user status")
	}
	var u discordUser
	err = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&u)
	if u.ID == "" {
		err = errors.New("invalid user response")
	}
	return u, err
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(s.sessionCookieName()); err == nil {
		_ = s.store.DeleteSession(r.Context(), s.hash(c.Value))
	}
	s.clearCookie(w, s.sessionCookieName())
	if wantsJSON(r) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) base(r *http.Request, title, page string) Page {
	c := current(r)
	return Page{Title: title, Page: page, CSRF: c.CSRF, User: c.User, TunnelDomain: s.cfg.TunnelDomain, SSHHost: s.cfg.SSHHost, SSHPort: s.cfg.SISHSSHPort, Flash: flash(r.URL.Query().Get("flash")), Error: r.URL.Query().Get("error")}
}
func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	p := s.base(r, "概要", "dashboard")
	p.Keys, _ = s.store.KeysByUser(r.Context(), p.User.ID)
	p.Subdomains, _ = s.store.SubdomainsByUser(r.Context(), p.User.ID)
	p.TCPPorts, _ = s.store.TCPPortsByUser(r.Context(), p.User.ID)
	p.Audit, _ = s.store.RecentAuditByUser(r.Context(), p.User.ID, 8)
	p.ActiveTunnels, _ = s.store.ActiveTunnels(r.Context(), &p.User.ID)
	if syncState, err := s.store.TunnelSyncState(r.Context()); err == nil {
		p.ActiveTunnelAvailable = syncState.Available
	}
	label := "myapp"
	if len(p.Subdomains) > 0 {
		label = p.Subdomains[0].Name
	}
	p.ConnectCommand = fmt.Sprintf("ssh -p %d -R %s:80:localhost:3000 %s", p.SSHPort, label, p.SSHHost)
	s.render(w, http.StatusOK, p)
}
func (s *Server) keysPage(w http.ResponseWriter, r *http.Request) {
	p := s.base(r, "SSH公開鍵", "keys")
	p.Keys, _ = s.store.KeysByUser(r.Context(), p.User.ID)
	s.render(w, http.StatusOK, p)
}
func (s *Server) keyAdd(w http.ResponseWriter, r *http.Request) {
	u := current(r).User
	_, err := s.svc.AddKey(r.Context(), u.ID, r.Form.Get("name"), r.Form.Get("public_key"), sourceIP(r))
	s.actionRedirect(w, r, "/keys", err, "key_added")
}
func (s *Server) keyEnable(w http.ResponseWriter, r *http.Request)  { s.keySet(w, r, false, true) }
func (s *Server) keyDisable(w http.ResponseWriter, r *http.Request) { s.keySet(w, r, false, false) }
func (s *Server) keySet(w http.ResponseWriter, r *http.Request, admin, enabled bool) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	err := s.svc.SetKeyEnabled(r.Context(), current(r).User.ID, admin, id, enabled, sourceIP(r))
	path := "/keys"
	if admin {
		path = "/admin/keys"
	}
	s.actionRedirect(w, r, path, err, "key_updated")
}
func (s *Server) keyDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	err := s.svc.DeleteKey(r.Context(), current(r).User.ID, false, id, sourceIP(r))
	s.actionRedirect(w, r, "/keys", err, "key_deleted")
}
func (s *Server) tunnelsPage(w http.ResponseWriter, r *http.Request) {
	p := s.base(r, "接続中のトンネル", "tunnels")
	uid := p.User.ID
	p.ActiveTunnels, _ = s.store.ActiveTunnels(r.Context(), &uid)
	if syncState, err := s.store.TunnelSyncState(r.Context()); err == nil {
		p.ActiveTunnelAvailable = syncState.Available
	}
	s.render(w, http.StatusOK, p)
}
func (s *Server) subdomainsPage(w http.ResponseWriter, r *http.Request) {
	p := s.base(r, "サブドメイン", "subdomains")
	p.Subdomains, _ = s.store.SubdomainsByUser(r.Context(), p.User.ID)
	s.render(w, http.StatusOK, p)
}
func (s *Server) subdomainReserve(w http.ResponseWriter, r *http.Request) {
	_, err := s.svc.ReserveSubdomain(r.Context(), current(r).User.ID, r.Form.Get("name"), sourceIP(r))
	s.actionRedirect(w, r, "/subdomains", err, "subdomain_reserved")
}
func (s *Server) subdomainRelease(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	err := s.svc.ReleaseSubdomain(r.Context(), current(r).User.ID, false, id, sourceIP(r))
	s.actionRedirect(w, r, "/subdomains", err, "subdomain_released")
}
func (s *Server) tcpPortsPage(w http.ResponseWriter, r *http.Request) {
	p := s.base(r, "TCPポート", "tcp-ports")
	p.TCPPorts, _ = s.store.TCPPortsByUser(r.Context(), p.User.ID)
	s.render(w, http.StatusOK, p)
}
func (s *Server) tcpPortReserve(w http.ResponseWriter, r *http.Request) {
	_, err := s.svc.ReserveTCPPort(r.Context(), current(r).User.ID, r.Form.Get("port"), sourceIP(r))
	s.actionRedirect(w, r, "/tcp-ports", err, "tcp_port_reserved")
}
func (s *Server) tcpPortRelease(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	err := s.svc.ReleaseTCPPort(r.Context(), current(r).User.ID, false, id, sourceIP(r))
	s.actionRedirect(w, r, "/tcp-ports", err, "tcp_port_released")
}
func (s *Server) adminHome(w http.ResponseWriter, r *http.Request) {
	p := s.base(r, "管理概要", "admin-home")
	p.Stats, _ = s.store.Stats(r.Context())
	p.Audit, _ = s.store.RecentAudit(r.Context(), 12)
	p.ActiveTunnels, _ = s.store.ActiveTunnels(r.Context(), nil)
	if syncState, err := s.store.TunnelSyncState(r.Context()); err == nil {
		p.ActiveTunnelAvailable = syncState.Available
	}
	s.render(w, http.StatusOK, p)
}
func (s *Server) adminUsers(w http.ResponseWriter, r *http.Request) {
	p := s.base(r, "ユーザー管理", "admin-users")
	page, pageSize, offset := requestedPage(r, "page", "per_page")
	var more bool
	var err error
	if p.Users, more, err = s.store.UsersPage(r.Context(), pageSize, offset); err != nil {
		s.internal(w, r, err)
		return
	}
	p.Pagination = pagination(r, "page", "per_page", page, pageSize, more)
	s.render(w, http.StatusOK, p)
}
func (s *Server) adminUserSuspend(w http.ResponseWriter, r *http.Request) { s.adminUserSet(w, r, true) }
func (s *Server) adminUserUnsuspend(w http.ResponseWriter, r *http.Request) {
	s.adminUserSet(w, r, false)
}
func (s *Server) adminUserSet(w http.ResponseWriter, r *http.Request, suspended bool) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	err := s.svc.SetUserSuspended(r.Context(), current(r).User.ID, id, suspended, sourceIP(r))
	s.actionRedirect(w, r, "/admin/users", err, "user_updated")
}
func (s *Server) adminKeys(w http.ResponseWriter, r *http.Request) {
	p := s.base(r, "全SSH公開鍵", "admin-keys")
	page, pageSize, offset := requestedPage(r, "page", "per_page")
	var more bool
	var err error
	if p.Keys, more, err = s.store.AllKeysPage(r.Context(), pageSize, offset); err != nil {
		s.internal(w, r, err)
		return
	}
	p.Pagination = pagination(r, "page", "per_page", page, pageSize, more)
	s.render(w, http.StatusOK, p)
}
func (s *Server) adminKeyEnable(w http.ResponseWriter, r *http.Request)  { s.keySet(w, r, true, true) }
func (s *Server) adminKeyDisable(w http.ResponseWriter, r *http.Request) { s.keySet(w, r, true, false) }
func (s *Server) adminKeyRevoke(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	err := s.svc.DeleteKey(r.Context(), current(r).User.ID, true, id, sourceIP(r))
	s.actionRedirect(w, r, "/admin/keys", err, "key_deleted")
}
func (s *Server) adminTunnels(w http.ResponseWriter, r *http.Request) {
	p := s.base(r, "接続中のトンネル", "admin-tunnels")
	page, pageSize, offset := requestedPage(r, "page", "per_page")
	var more bool
	var err error
	if p.ActiveTunnels, more, err = s.store.ActiveTunnelsPage(r.Context(), nil, pageSize, offset); err != nil {
		s.internal(w, r, err)
		return
	}
	p.Pagination = pagination(r, "page", "per_page", page, pageSize, more)
	if syncState, err := s.store.TunnelSyncState(r.Context()); err == nil {
		p.ActiveTunnelAvailable = syncState.Available
	}
	s.render(w, http.StatusOK, p)
}
func (s *Server) adminSecurity(w http.ResponseWriter, r *http.Request) {
	p := s.base(r, "セキュリティ検知", "admin-security")
	page, pageSize, offset := requestedPage(r, "page", "per_page")
	var more bool
	var err error
	if p.SecurityMetrics, more, err = s.store.SecurityTelemetryPage(r.Context(), pageSize, offset); err != nil {
		s.internal(w, r, err)
		return
	}
	p.Pagination = pagination(r, "page", "per_page", page, pageSize, more)
	s.render(w, http.StatusOK, p)
}
func (s *Server) adminSubdomains(w http.ResponseWriter, r *http.Request) {
	p := s.base(r, "全サブドメイン", "admin-subdomains")
	page, pageSize, offset := requestedPage(r, "page", "per_page")
	var more bool
	var err error
	if p.Subdomains, more, err = s.store.AllSubdomainsPage(r.Context(), pageSize, offset); err != nil {
		s.internal(w, r, err)
		return
	}
	p.Pagination = pagination(r, "page", "per_page", page, pageSize, more)
	for i := range p.Subdomains {
		conflict, err := s.svc.DNS.HasExactRecord(r.Context(), p.Subdomains[i].Name)
		switch {
		case err != nil:
			p.Subdomains[i].DNSConflict = "Unavailable"
		case conflict:
			p.Subdomains[i].DNSConflict = "Conflict"
		default:
			p.Subdomains[i].DNSConflict = "None"
		}
	}
	s.render(w, http.StatusOK, p)
}
func (s *Server) adminTCPPorts(w http.ResponseWriter, r *http.Request) {
	p := s.base(r, "全TCPポート", "admin-tcp-ports")
	page, pageSize, offset := requestedPage(r, "page", "per_page")
	var more bool
	var err error
	if p.TCPPorts, more, err = s.store.AllTCPPortsPage(r.Context(), pageSize, offset); err != nil {
		s.internal(w, r, err)
		return
	}
	p.Pagination = pagination(r, "page", "per_page", page, pageSize, more)
	s.render(w, http.StatusOK, p)
}
func (s *Server) adminTCPPortRelease(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	err := s.svc.ReleaseTCPPort(r.Context(), current(r).User.ID, true, id, sourceIP(r))
	s.actionRedirect(w, r, "/admin/tcp-ports", err, "tcp_port_released")
}
func (s *Server) adminSubdomainRelease(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	err := s.svc.ReleaseSubdomain(r.Context(), current(r).User.ID, true, id, sourceIP(r))
	s.actionRedirect(w, r, "/admin/subdomains", err, "subdomain_released")
}

func requestedPage(r *http.Request, pageParameter, _ string) (int, int, int) {
	page, err := strconv.Atoi(r.URL.Query().Get(pageParameter))
	if err != nil || page < 1 || page > 1_000_000 {
		page = 1
	}
	return page, defaultAdminPageSize, (page - 1) * defaultAdminPageSize
}
func pagination(r *http.Request, pageParameter, sizeParameter string, page, _ int, hasMore bool) Pagination {
	p := Pagination{Page: page}
	pageURL := func(n int) string {
		q := r.URL.Query()
		if n == 1 {
			q.Del(pageParameter)
		} else {
			q.Set(pageParameter, strconv.Itoa(n))
		}
		q.Del(sizeParameter)
		if encoded := q.Encode(); encoded != "" {
			return r.URL.Path + "?" + encoded
		}
		return r.URL.Path
	}
	if page > 1 {
		p.PreviousURL = pageURL(page - 1)
	}
	if hasMore {
		p.NextURL = pageURL(page + 1)
	}
	return p
}

func (s *Server) render(w http.ResponseWriter, status int, p Page) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(newPageDTO(p)); err != nil {
		s.logger.Error("JSON rendering failed", "error", err)
	}
}
func (s *Server) internal(w http.ResponseWriter, r *http.Request, err error) {
	s.logger.Error("request failed", "path", r.URL.Path, "error", err)
	http.Error(w, "Internal server error", http.StatusInternalServerError)
}
func (s *Server) actionRedirect(w http.ResponseWriter, r *http.Request, path string, err error, ok string) {
	q := url.Values{}
	if err != nil {
		q.Set("error", publicError(err))
	} else {
		q.Set("flash", ok)
	}
	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		status := http.StatusOK
		if err != nil {
			status = http.StatusUnprocessableEntity
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"flash": flash(ok), "error": q.Get("error")})
		return
	}
	http.Redirect(w, r, path+"?"+q.Encode(), http.StatusSeeOther)
}
func wantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "application/json")
}
func publicError(err error) string {
	known := []error{service.ErrInvalidKey, service.ErrKeyTooLarge, service.ErrDuplicateKey, service.ErrForbidden, service.ErrSuspended, service.ErrInvalidSubdomain, service.ErrReservedSubdomain, service.ErrDuplicateSubdomain, service.ErrDNSConflict, service.ErrDNSUnavailable, service.ErrInvalidTCPPort, service.ErrDuplicateTCPPort}
	for _, e := range known {
		if errors.Is(err, e) {
			return e.Error()
		}
	}
	if service.IsNotFound(err) {
		return "対象が見つかりません"
	}
	return "操作を完了できませんでした"
}
func flash(v string) string {
	m := map[string]string{"login": "ログインしました", "key_added": "SSH公開鍵を追加しました", "key_updated": "SSH公開鍵を更新しました", "key_deleted": "SSH公開鍵を削除しました", "subdomain_reserved": "サブドメインを予約しました", "subdomain_released": "サブドメインを解放しました", "tcp_port_reserved": "TCPポートを予約しました", "tcp_port_released": "TCPポートを解放しました", "user_updated": "ユーザー状態を更新しました"}
	return m[v]
}
func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}
func sourceIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("system random unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func sha(v string) string { x := sha256.Sum256([]byte(v)); return hex.EncodeToString(x[:]) }
func (s *Server) hash(v string) string {
	m := hmac.New(sha256.New, []byte(s.cfg.SessionSecret))
	m.Write([]byte(v))
	return hex.EncodeToString(m.Sum(nil))
}
func (s *Server) sessionCookieName() string {
	if s.cfg.CookieSecure {
		return secureSessionCookie
	}
	return sessionCookie
}
func (s *Server) oauthCookieName() string {
	if s.cfg.CookieSecure {
		return secureOAuthCookie
	}
	return oauthCookie
}
func (s *Server) authCookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: maxAge, HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode}
}
func (s *Server) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, s.authCookie(name, "", -1))
}

var _ integration.TunnelProvider = integration.UnavailableTunnelProvider{}
