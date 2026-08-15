package web

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"tunnel-control-plane/internal/model"
	"tunnel-control-plane/internal/store"
)

type InternalServer struct {
	Store             *store.Store
	TokenFile, Domain string
}
type bindAuthorization struct {
	Fingerprint string `json:"fingerprint"`
	SSHUser     string `json:"ssh_user"`
	Protocol    string `json:"protocol"`
	Hostname    string `json:"hostname"`
	Port        int    `json:"port"`
	SourceIP    string `json:"source_ip"`
}
type tunnelEvent struct {
	EventID     string    `json:"event_id"`
	SourceID    string    `json:"source_id"`
	ID          string    `json:"id"`
	UserID      int64     `json:"user_id"`
	KeyID       int64     `json:"key_id"`
	Generation  int64     `json:"generation"`
	Sequence    int64     `json:"sequence"`
	Protocol    string    `json:"protocol"`
	Hostname    string    `json:"hostname"`
	SourceIP    string    `json:"source_ip"`
	Port        int       `json:"port"`
	ConnectedAt time.Time `json:"connected_at"`
}

func (s InternalServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/authorize", s.authorize)
	mux.HandleFunc("POST /v1/tunnels/connect", s.connect)
	mux.HandleFunc("POST /v1/tunnels/{id}/disconnect", s.disconnect)
	mux.HandleFunc("POST /v1/telemetry", s.telemetry)
	return s.protect(mux)
}
func (s InternalServer) protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || !net.ParseIP(host).IsLoopback() {
			http.Error(w, "Forbidden", 403)
			return
		}
		b, err := os.ReadFile(s.TokenFile)
		if err != nil {
			http.Error(w, "Unavailable", 503)
			return
		}
		want := strings.TrimSpace(string(b))
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if len(want) < 32 || len(got) != len(want) || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			http.Error(w, "Unauthorized", 401)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		next.ServeHTTP(w, r)
	})
}
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	d := json.NewDecoder(io.LimitReader(r.Body, 16<<10))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

// canonicalHost is the single hostname boundary used by authorization,
// lifecycle registration, snapshots, disconnect selectors and storage.
func canonicalHost(host, domain string) (label, fqdn string, err error) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" {
		return "", "", errors.New("empty domain")
	}
	if strings.HasSuffix(host, "."+domain) {
		host = strings.TrimSuffix(host, "."+domain)
	}
	if host == "" || strings.Contains(host, ".") || len(host) > 63 || host[0] == '-' || host[len(host)-1] == '-' {
		return "", "", errors.New("invalid host")
	}
	for _, r := range host {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return "", "", errors.New("invalid host")
		}
	}
	return host, host + "." + domain, nil
}
func (s InternalServer) authorize(w http.ResponseWriter, r *http.Request) {
	var q bindAuthorization
	if decodeJSON(w, r, &q) != nil {
		http.Error(w, "Bad request", 400)
		return
	}
	q.Protocol = strings.ToLower(q.Protocol)
	label, fqdn, err := canonicalHost(q.Hostname, s.Domain)
	if err != nil && (q.Protocol == "http" || q.Protocol == "https" || q.Protocol == "tls") {
		http.Error(w, "Forbidden", 403)
		return
	}
	if q.Protocol == "tcp" {
		label = ""
		fqdn = ""
	}
	k, g, err := s.Store.AuthorizeBind(r.Context(), q.Fingerprint, label, q.Protocol, q.Port)
	if err != nil {
		http.Error(w, "Forbidden", 403)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"allowed": true, "user_id": k.UserID, "key_id": k.ID, "generation": g, "hostname": fqdn})
}
func (s InternalServer) connect(w http.ResponseWriter, r *http.Request) {
	var e tunnelEvent
	if decodeJSON(w, r, &e) != nil || e.EventID == "" || e.SourceID == "" || e.ID == "" || e.UserID < 1 || e.KeyID < 1 || e.Generation < 1 || e.Sequence < 1 {
		http.Error(w, "Bad request", 400)
		return
	}
	e.Protocol = strings.ToLower(e.Protocol)
	label, fqdn, err := canonicalHost(e.Hostname, s.Domain)
	if e.Protocol == "tcp" {
		label = ""
		fqdn = ""
	} else if err != nil {
		http.Error(w, "Bad request", 400)
		return
	}
	if e.ConnectedAt.IsZero() {
		e.ConnectedAt = time.Now()
	}
	err = s.Store.ApplyTunnelConnect(r.Context(), model.ActiveTunnel{ID: e.ID, UserID: e.UserID, SSHKeyID: e.KeyID, Protocol: e.Protocol, Hostname: fqdn, TCPPort: e.Port, SourceIP: e.SourceIP, Generation: e.Generation, EventSequence: e.Sequence, ConnectedAt: e.ConnectedAt}, label, e.SourceID, e.EventID)
	if err != nil {
		http.Error(w, "Unavailable", 503)
		return
	}
	w.WriteHeader(204)
}
func (s InternalServer) disconnect(w http.ResponseWriter, r *http.Request) {
	var q struct {
		EventID        string    `json:"event_id"`
		SourceID       string    `json:"source_id"`
		Sequence       int64     `json:"sequence"`
		DisconnectedAt time.Time `json:"disconnected_at"`
	}
	if decodeJSON(w, r, &q) != nil || q.EventID == "" || q.SourceID == "" || q.Sequence < 1 {
		http.Error(w, "Bad request", 400)
		return
	}
	if q.DisconnectedAt.IsZero() {
		q.DisconnectedAt = time.Now()
	}
	if err := s.Store.ApplyTunnelDisconnect(r.Context(), r.PathValue("id"), q.SourceID, q.EventID, q.Sequence, q.DisconnectedAt); err != nil {
		http.Error(w, "Unavailable", 503)
		return
	}
	w.WriteHeader(204)
}
func (s InternalServer) telemetry(w http.ResponseWriter, r *http.Request) {
	var q struct {
		EventID string           `json:"event_id"`
		Events  map[string]int64 `json:"events"`
	}
	if decodeJSON(w, r, &q) != nil || q.EventID == "" || len(q.Events) == 0 || len(q.Events) > 16 {
		http.Error(w, "Bad request", 400)
		return
	}
	allowed := map[string]bool{"unknown_host": true, "rate_limited": true, "temporarily_blocked": true, "connection_limited": true, "authorization_denied": true}
	for k, n := range q.Events {
		if !allowed[k] || n < 1 || n > 1_000_000 {
			http.Error(w, "Bad request", 400)
			return
		}
	}
	if err := s.Store.AddSecurityTelemetryBatch(r.Context(), q.EventID, q.Events); err != nil {
		http.Error(w, "Unavailable", 503)
		return
	}
	w.WriteHeader(204)
}
