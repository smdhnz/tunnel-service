package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
	"tunnel-control-plane/internal/model"
)

type Store struct{ DB *sql.DB }

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, p := range []string{"PRAGMA journal_mode=WAL", "PRAGMA busy_timeout=5000", "PRAGMA foreign_keys=ON"} {
		if _, err = db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("sqlite setup: %w", err)
		}
	}
	s := &Store{DB: db}
	if err = s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) Close() error { return s.DB.Close() }
func (s *Store) migrate() error {
	entries, err := fs.ReadDir(migrations, "migrations")
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		v, err := strconv.Atoi(strings.SplitN(e.Name(), "_", 2)[0])
		if err != nil {
			return err
		}
		var exists int
		_ = s.DB.QueryRow("SELECT count(*) FROM schema_migrations WHERE version=?", v).Scan(&exists)
		if exists > 0 {
			continue
		}
		b, err := migrations.ReadFile("migrations/" + e.Name())
		if err != nil {
			return err
		}
		tx, err := s.DB.Begin()
		if err != nil {
			return err
		}
		if _, err = tx.Exec(string(b)); err == nil {
			_, err = tx.Exec("INSERT OR IGNORE INTO schema_migrations(version) VALUES(?)", v)
		}
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %s: %w", e.Name(), err)
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) UpsertDiscordUser(ctx context.Context, discordID, username, displayName, email, avatar, role string) (*model.User, error) {
	_, err := s.DB.ExecContext(ctx, `INSERT INTO users(discord_id,username,display_name,email,avatar_url,role) VALUES(?,?,?,?,?,?)
 ON CONFLICT(discord_id) DO UPDATE SET username=excluded.username,display_name=excluded.display_name,email=excluded.email,avatar_url=excluded.avatar_url,role=excluded.role,updated_at=CURRENT_TIMESTAMP`, discordID, username, displayName, email, avatar, role)
	if err != nil {
		return nil, err
	}
	return s.UserByDiscordID(ctx, discordID)
}
func scanUser(row interface{ Scan(...any) error }) (*model.User, error) {
	var u model.User
	var c, a string
	err := row.Scan(&u.ID, &u.DiscordID, &u.Username, &u.DisplayName, &u.Email, &u.AvatarURL, &u.Role, &u.Status, &c, &a)
	u.CreatedAt = parseTime(c)
	u.UpdatedAt = parseTime(a)
	return &u, err
}
func userCols() string {
	return `id,discord_id,username,display_name,email,avatar_url,role,status,created_at,updated_at`
}
func (s *Store) UserByDiscordID(ctx context.Context, id string) (*model.User, error) {
	return scanUser(s.DB.QueryRowContext(ctx, "SELECT "+userCols()+" FROM users WHERE discord_id=?", id))
}
func (s *Store) UserByID(ctx context.Context, id int64) (*model.User, error) {
	return scanUser(s.DB.QueryRowContext(ctx, "SELECT "+userCols()+" FROM users WHERE id=?", id))
}
func (s *Store) Users(ctx context.Context) ([]model.User, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT u.id,u.discord_id,u.username,u.display_name,u.email,u.avatar_url,u.role,u.status,u.created_at,u.updated_at,(SELECT count(*) FROM ssh_keys k WHERE k.user_id=u.id),(SELECT count(*) FROM subdomains d WHERE d.user_id=u.id),(SELECT count(*) FROM tcp_ports p WHERE p.user_id=u.id) FROM users u ORDER BY u.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.User
	for rows.Next() {
		var u model.User
		var c, a string
		if err = rows.Scan(&u.ID, &u.DiscordID, &u.Username, &u.DisplayName, &u.Email, &u.AvatarURL, &u.Role, &u.Status, &c, &a, &u.SSHKeyCount, &u.SubdomainCount, &u.TCPPortCount); err != nil {
			return nil, err
		}
		u.CreatedAt = parseTime(c)
		u.UpdatedAt = parseTime(a)
		out = append(out, u)
	}
	return out, rows.Err()
}
func (s *Store) SetUserStatus(ctx context.Context, id int64, status string) error {
	r, err := s.DB.ExecContext(ctx, "UPDATE users SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?", status, id)
	return requireAffected(r, err)
}
func (s *Store) DeleteUserSessions(ctx context.Context, id int64) error {
	_, err := s.DB.ExecContext(ctx, "DELETE FROM sessions WHERE user_id=?", id)
	return err
}

func (s *Store) CreateOAuthState(ctx context.Context, h string, exp time.Time) error {
	_, err := s.DB.ExecContext(ctx, "INSERT INTO oauth_states(state_hash,expires_at) VALUES(?,?)", h, exp.UTC().Format(time.RFC3339Nano))
	return err
}
func (s *Store) ConsumeOAuthState(ctx context.Context, h string, now time.Time) (bool, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var exp string
	if err = tx.QueryRowContext(ctx, "SELECT expires_at FROM oauth_states WHERE state_hash=?", h).Scan(&exp); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM oauth_states WHERE state_hash=?", h); err != nil {
		return false, err
	}
	if err = tx.Commit(); err != nil {
		return false, err
	}
	return parseTime(exp).After(now), nil
}
func (s *Store) CreateSession(ctx context.Context, h string, userID int64, csrf string, exp time.Time) error {
	_, err := s.DB.ExecContext(ctx, "INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at) VALUES(?,?,?,?)", h, userID, csrf, exp.UTC().Format(time.RFC3339Nano))
	return err
}
func (s *Store) SessionUser(ctx context.Context, h string, now time.Time) (*model.User, string, error) {
	row := s.DB.QueryRowContext(ctx, `SELECT u.id,u.discord_id,u.username,u.display_name,u.email,u.avatar_url,u.role,u.status,u.created_at,u.updated_at,s.csrf_token FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?`, h, now.UTC().Format(time.RFC3339Nano))
	var u model.User
	var c, a, csrf string
	err := row.Scan(&u.ID, &u.DiscordID, &u.Username, &u.DisplayName, &u.Email, &u.AvatarURL, &u.Role, &u.Status, &c, &a, &csrf)
	u.CreatedAt = parseTime(c)
	u.UpdatedAt = parseTime(a)
	return &u, csrf, err
}
func (s *Store) DeleteSession(ctx context.Context, h string) error {
	_, err := s.DB.ExecContext(ctx, "DELETE FROM sessions WHERE token_hash=?", h)
	return err
}
func (s *Store) CleanupAuth(ctx context.Context, now time.Time) error {
	_, sessionErr := s.DB.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at<=?", now.UTC().Format(time.RFC3339Nano))
	_, stateErr := s.DB.ExecContext(ctx, "DELETE FROM oauth_states WHERE expires_at<=?", now.UTC().Format(time.RFC3339Nano))
	return errors.Join(sessionErr, stateErr)
}

func scanKey(row interface{ Scan(...any) error }) (model.SSHKey, error) {
	var k model.SSHKey
	var enabled int
	var c, u string
	err := row.Scan(&k.ID, &k.UserID, &k.Owner, &k.Name, &k.PublicKey, &k.Fingerprint, &enabled, &c, &u)
	k.Enabled = enabled == 1
	k.CreatedAt = parseTime(c)
	k.UpdatedAt = parseTime(u)
	return k, err
}
func (s *Store) KeysByUser(ctx context.Context, uid int64) ([]model.SSHKey, error) {
	return s.keys(ctx, "WHERE k.user_id=?", uid)
}
func (s *Store) AllKeys(ctx context.Context) ([]model.SSHKey, error) { return s.keys(ctx, "", nil) }
func (s *Store) keys(ctx context.Context, where string, arg any) ([]model.SSHKey, error) {
	q := `SELECT k.id,k.user_id,u.username,k.name,k.public_key,k.fingerprint,k.enabled,k.created_at,k.updated_at FROM ssh_keys k JOIN users u ON u.id=k.user_id ` + where + ` ORDER BY k.created_at DESC`
	var rows *sql.Rows
	var err error
	if where == "" {
		rows, err = s.DB.QueryContext(ctx, q)
	} else {
		rows, err = s.DB.QueryContext(ctx, q, arg)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.SSHKey
	for rows.Next() {
		k, e := scanKey(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, k)
	}
	return out, rows.Err()
}
func (s *Store) Key(ctx context.Context, id int64) (model.SSHKey, error) {
	return scanKey(s.DB.QueryRowContext(ctx, `SELECT k.id,k.user_id,u.username,k.name,k.public_key,k.fingerprint,k.enabled,k.created_at,k.updated_at FROM ssh_keys k JOIN users u ON u.id=k.user_id WHERE k.id=?`, id))
}
func (s *Store) InsertKey(ctx context.Context, uid int64, name, key, fp string) (int64, error) {
	r, err := s.DB.ExecContext(ctx, "INSERT INTO ssh_keys(user_id,name,public_key,fingerprint) VALUES(?,?,?,?)", uid, name, key, fp)
	if err != nil {
		return 0, err
	}
	return r.LastInsertId()
}
func (s *Store) SetKeyEnabled(ctx context.Context, id int64, en bool) error {
	r, err := s.DB.ExecContext(ctx, "UPDATE ssh_keys SET enabled=?,updated_at=CURRENT_TIMESTAMP WHERE id=?", en, id)
	return requireAffected(r, err)
}
func (s *Store) DeleteKey(ctx context.Context, id int64) error {
	r, err := s.DB.ExecContext(ctx, "DELETE FROM ssh_keys WHERE id=?", id)
	return requireAffected(r, err)
}
func (s *Store) AuthorizedKeys(ctx context.Context) ([]model.SSHKey, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT k.id,k.user_id,u.username,k.name,k.public_key,k.fingerprint,k.enabled,k.created_at,k.updated_at FROM ssh_keys k JOIN users u ON u.id=k.user_id WHERE k.enabled=1 AND u.status='active'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.SSHKey
	for rows.Next() {
		k, e := scanKey(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) SubdomainsByUser(ctx context.Context, uid int64) ([]model.Subdomain, error) {
	return s.subdomains(ctx, "WHERE d.user_id=?", uid)
}
func (s *Store) AllSubdomains(ctx context.Context) ([]model.Subdomain, error) {
	return s.subdomains(ctx, "", nil)
}
func (s *Store) subdomains(ctx context.Context, where string, arg any) ([]model.Subdomain, error) {
	q := `SELECT d.id,d.user_id,u.username,d.name,d.status,d.created_at,d.updated_at FROM subdomains d JOIN users u ON u.id=d.user_id ` + where + ` ORDER BY d.created_at DESC`
	var rows *sql.Rows
	var err error
	if where == "" {
		rows, err = s.DB.QueryContext(ctx, q)
	} else {
		rows, err = s.DB.QueryContext(ctx, q, arg)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Subdomain
	for rows.Next() {
		var d model.Subdomain
		var c, u string
		if err = rows.Scan(&d.ID, &d.UserID, &d.Owner, &d.Name, &d.Status, &c, &u); err != nil {
			return nil, err
		}
		d.CreatedAt = parseTime(c)
		d.UpdatedAt = parseTime(u)
		out = append(out, d)
	}
	return out, rows.Err()
}
func (s *Store) Subdomain(ctx context.Context, id int64) (model.Subdomain, error) {
	var d model.Subdomain
	var c, u string
	err := s.DB.QueryRowContext(ctx, `SELECT d.id,d.user_id,u.username,d.name,d.status,d.created_at,d.updated_at FROM subdomains d JOIN users u ON u.id=d.user_id WHERE d.id=?`, id).Scan(&d.ID, &d.UserID, &d.Owner, &d.Name, &d.Status, &c, &u)
	d.CreatedAt = parseTime(c)
	d.UpdatedAt = parseTime(u)
	return d, err
}
func (s *Store) InsertSubdomain(ctx context.Context, uid int64, name string) (int64, error) {
	r, err := s.DB.ExecContext(ctx, "INSERT INTO subdomains(user_id,name) VALUES(?,?)", uid, name)
	if err != nil {
		return 0, err
	}
	return r.LastInsertId()
}
func (s *Store) DeleteSubdomain(ctx context.Context, id int64) error {
	r, err := s.DB.ExecContext(ctx, "DELETE FROM subdomains WHERE id=?", id)
	return requireAffected(r, err)
}

func (s *Store) TCPPortsByUser(ctx context.Context, uid int64) ([]model.TCPPort, error) {
	return s.tcpPorts(ctx, "WHERE p.user_id=?", uid)
}
func (s *Store) AllTCPPorts(ctx context.Context) ([]model.TCPPort, error) {
	return s.tcpPorts(ctx, "", nil)
}
func (s *Store) tcpPorts(ctx context.Context, where string, arg any) ([]model.TCPPort, error) {
	q := `SELECT p.id,p.user_id,u.username,p.port,p.created_at,p.updated_at FROM tcp_ports p JOIN users u ON u.id=p.user_id ` + where + ` ORDER BY p.port`
	var rows *sql.Rows
	var err error
	if where == "" {
		rows, err = s.DB.QueryContext(ctx, q)
	} else {
		rows, err = s.DB.QueryContext(ctx, q, arg)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.TCPPort
	for rows.Next() {
		var p model.TCPPort
		var c, u string
		if err = rows.Scan(&p.ID, &p.UserID, &p.Owner, &p.Port, &c, &u); err != nil {
			return nil, err
		}
		p.CreatedAt, p.UpdatedAt = parseTime(c), parseTime(u)
		out = append(out, p)
	}
	return out, rows.Err()
}
func (s *Store) TCPPort(ctx context.Context, id int64) (model.TCPPort, error) {
	var p model.TCPPort
	var c, u string
	err := s.DB.QueryRowContext(ctx, `SELECT p.id,p.user_id,u.username,p.port,p.created_at,p.updated_at FROM tcp_ports p JOIN users u ON u.id=p.user_id WHERE p.id=?`, id).Scan(&p.ID, &p.UserID, &p.Owner, &p.Port, &c, &u)
	p.CreatedAt, p.UpdatedAt = parseTime(c), parseTime(u)
	return p, err
}

func (s *Store) Audit(ctx context.Context, actor, target *int64, action, typ, rid, ip, metadata string) error {
	_, err := s.DB.ExecContext(ctx, "INSERT INTO audit_logs(actor_user_id,target_user_id,action,resource_type,resource_id,source_ip,metadata) VALUES(?,?,?,?,?,?,?)", actor, target, action, typ, rid, ip, metadata)
	return err
}
func (s *Store) RecentAudit(ctx context.Context, limit int) ([]model.AuditLog, error) {
	return s.recentAudit(ctx, "", limit, nil)
}
func (s *Store) RecentAuditByUser(ctx context.Context, userID int64, limit int) ([]model.AuditLog, error) {
	return s.recentAudit(ctx, "WHERE actor_user_id=?", limit, userID)
}
func (s *Store) recentAudit(ctx context.Context, where string, limit int, arg any) ([]model.AuditLog, error) {
	query := `SELECT id,actor_user_id,target_user_id,action,resource_type,resource_id,source_ip,metadata,created_at FROM audit_logs ` + where + ` ORDER BY created_at DESC LIMIT ?`
	var rows *sql.Rows
	var err error
	if where == "" {
		rows, err = s.DB.QueryContext(ctx, query, limit)
	} else {
		rows, err = s.DB.QueryContext(ctx, query, arg, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.AuditLog
	for rows.Next() {
		var a model.AuditLog
		var actor, target sql.NullInt64
		var c string
		if err = rows.Scan(&a.ID, &actor, &target, &a.Action, &a.ResourceType, &a.ResourceID, &a.SourceIP, &a.Metadata, &c); err != nil {
			return nil, err
		}
		if actor.Valid {
			a.ActorUserID = &actor.Int64
		}
		if target.Valid {
			a.TargetUserID = &target.Int64
		}
		a.CreatedAt = parseTime(c)
		out = append(out, a)
	}
	return out, rows.Err()
}
func (s *Store) Stats(ctx context.Context) (model.Stats, error) {
	var st model.Stats
	err := s.DB.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM users),(SELECT count(*) FROM users WHERE status='active'),(SELECT count(*) FROM ssh_keys),(SELECT count(*) FROM subdomains),(SELECT count(*) FROM tcp_ports),(SELECT count(*) FROM users WHERE status='suspended'),(SELECT count(*) FROM active_tunnels WHERE status='active')`).Scan(&st.Users, &st.ActiveUsers, &st.SSHKeys, &st.Subdomains, &st.TCPPorts, &st.SuspendedUsers, &st.ActiveTunnels)
	return st, err
}

func requireAffected(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func parseTime(v string) time.Time {
	layouts := []string{time.RFC3339Nano, "2006-01-02 15:04:05"}
	for _, l := range layouts {
		if t, e := time.Parse(l, v); e == nil {
			return t
		}
	}
	return time.Time{}
}
