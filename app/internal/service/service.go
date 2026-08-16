package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"golang.org/x/crypto/ssh"
	"tunnel-control-plane/internal/integration"
	"tunnel-control-plane/internal/model"
	"tunnel-control-plane/internal/store"
)

var (
	ErrInvalidKey         = errors.New("OpenSSH形式の公開鍵を入力してください")
	ErrKeyTooLarge        = errors.New("公開鍵がサイズ上限を超えています")
	ErrDuplicateKey       = errors.New("この公開鍵は登録済みです")
	ErrForbidden          = errors.New("操作する権限がありません")
	ErrSuspended          = errors.New("アカウントは停止されています")
	ErrInvalidSubdomain   = errors.New("英小文字、数字、ハイフンのみで1〜63文字を入力してください")
	ErrReservedSubdomain  = errors.New("このサブドメインは予約済みです")
	ErrDuplicateSubdomain = errors.New("このサブドメインは既に予約されています")
	ErrDNSConflict        = errors.New("既存のDNSレコードと競合しています")
	ErrDNSUnavailable     = errors.New("DNS競合を確認できないため予約できません")
)

const MaxPublicKeyBytes = 16 * 1024

var ReservedSubdomains = map[string]struct{}{"ssh": {}, "tunnel": {}, "www": {}, "api": {}, "admin": {}, "auth": {}, "app": {}, "status": {}, "mail": {}, "smtp": {}, "ftp": {}, "ns1": {}, "ns2": {}, "_acme-challenge": {}}

type PublicKeyStore interface {
	Write(model.SSHKey) error
	Remove(userID, keyID int64) error
	Reconcile([]model.SSHKey) error
}

type Service struct {
	Store   *store.Store
	DNS     integration.DNSChecker
	Keys    PublicKeyStore
	Logger  *slog.Logger
	Tunnels TunnelController

	keyMu sync.Mutex
}

func ValidatePublicKey(raw string) (string, string, error) {
	if len(raw) > MaxPublicKeyBytes {
		return "", "", ErrKeyTooLarge
	}
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsRune(raw, '\x00') {
		return "", "", ErrInvalidKey
	}
	key, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(raw))
	if err != nil || len(options) > 0 || len(strings.TrimSpace(string(rest))) > 0 {
		return "", "", ErrInvalidKey
	}
	canonical := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	if comment != "" {
		canonical += " " + strings.TrimSpace(comment)
	}
	return canonical, ssh.FingerprintSHA256(key), nil
}
func NormalizeSubdomain(raw string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(raw))
	if _, ok := ReservedSubdomains[name]; ok {
		return "", ErrReservedSubdomain
	}
	if len(name) < 1 || len(name) > 63 || name[0] == '-' || name[len(name)-1] == '-' {
		return "", ErrInvalidSubdomain
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') || unicode.IsSpace(r) {
			return "", ErrInvalidSubdomain
		}
	}
	return name, nil
}
func cleanName(name string) error {
	name = strings.TrimSpace(name)
	if len(name) < 1 || len(name) > 80 {
		return errors.New("名前は1〜80文字で入力してください")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return errors.New("名前に制御文字は使えません")
		}
	}
	return nil
}
func (s *Service) ensureActive(ctx context.Context, uid int64) error {
	u, err := s.Store.UserByID(ctx, uid)
	if err != nil {
		return err
	}
	if u.Status != "active" {
		return ErrSuspended
	}
	return nil
}
func (s *Service) syncLocked(ctx context.Context) error {
	keys, err := s.Store.AuthorizedKeys(ctx)
	if err != nil {
		return err
	}
	return s.Keys.Reconcile(keys)
}
func (s *Service) Reconcile(ctx context.Context) error {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	return s.syncLocked(ctx)
}
func (s *Service) AddKey(ctx context.Context, uid int64, name, raw, ip string) (int64, error) {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	if err := s.ensureActive(ctx, uid); err != nil {
		return 0, err
	}
	if err := cleanName(name); err != nil {
		return 0, err
	}
	key, fp, err := ValidatePublicKey(raw)
	if err != nil {
		return 0, err
	}
	id, err := s.Store.InsertKeyAtomic(ctx, uid, strings.TrimSpace(name), key, fp, store.AuditEntry{Actor: &uid, Target: &uid, Action: "ssh_key.add", ResourceType: "ssh_key", SourceIP: ip})
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return 0, ErrDuplicateKey
		}
		return 0, err
	}
	created, err := s.Store.Key(ctx, id)
	if err == nil {
		err = s.Keys.Write(created)
	}
	if err != nil {
		// A failed write may have reached rename. Remove authorization before
		// rolling the DB row back. If removal itself fails, keep the enabled DB
		// row so reconciliation never loses track of a possibly authorized file.
		removeErr := s.Keys.Remove(uid, id)
		if removeErr != nil {
			return 0, fmt.Errorf("公開鍵の反映と失効に失敗しました: %w", errors.Join(err, removeErr))
		}
		deleteErr := s.Store.DeleteKey(ctx, id)
		if deleteErr != nil {
			_ = s.Store.SetKeyEnabled(ctx, id, false)
		}
		return 0, fmt.Errorf("公開鍵の反映に失敗しました: %w", errors.Join(err, deleteErr))
	}
	return id, nil
}
func (s *Service) SetKeyEnabled(ctx context.Context, actor int64, admin bool, id int64, enabled bool, ip string) error {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	k, err := s.Store.Key(ctx, id)
	if err != nil {
		return err
	}
	if !admin && k.UserID != actor {
		return ErrForbidden
	}
	if err = s.ensureActive(ctx, k.UserID); err != nil {
		return err
	}
	if enabled {
		k.Enabled = true
		if err = s.Keys.Write(k); err != nil {
			return err
		}
	} else {
		// Revoke filesystem authorization before changing the DB. If the DB
		// update fails, the mismatch denies access rather than granting it.
		if err = s.Keys.Remove(k.UserID, k.ID); err != nil {
			return err
		}
	}
	action := "ssh_key.disable"
	if enabled {
		action = "ssh_key.enable"
	}
	if admin {
		action = "admin." + action
	}
	if err = s.Store.SetKeyEnabledAtomic(ctx, id, enabled, store.AuditEntry{Actor: &actor, Target: &k.UserID, Action: action, ResourceType: "ssh_key", ResourceID: strconv.FormatInt(id, 10), SourceIP: ip}); err != nil {
		if enabled {
			_ = s.Keys.Remove(k.UserID, k.ID)
		}
		return err
	}
	return nil
}
func (s *Service) DeleteKey(ctx context.Context, actor int64, admin bool, id int64, ip string) error {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	k, err := s.Store.Key(ctx, id)
	if err != nil {
		return err
	}
	if !admin && k.UserID != actor {
		return ErrForbidden
	}
	if err = s.Keys.Remove(k.UserID, k.ID); err != nil {
		return err
	}
	action := "ssh_key.delete"
	if admin {
		action = "admin.ssh_key.revoke"
	}
	if err = s.Store.DeleteKeyAtomic(ctx, id, k.UserID, store.AuditEntry{Actor: &actor, Target: &k.UserID, Action: action, ResourceType: "ssh_key", ResourceID: strconv.FormatInt(id, 10), SourceIP: ip}); err != nil {
		return err
	}
	return nil
}
func (s *Service) ReserveSubdomain(ctx context.Context, uid int64, raw, ip string) (int64, error) {
	if err := s.ensureActive(ctx, uid); err != nil {
		return 0, err
	}
	name := strings.ToLower(strings.TrimSpace(raw))
	if name == "tunnel" {
		u, err := s.Store.UserByID(ctx, uid)
		if err != nil {
			return 0, err
		}
		if u.Role != "admin" {
			return 0, ErrReservedSubdomain
		}
	} else {
		var err error
		name, err = NormalizeSubdomain(name)
		if err != nil {
			return 0, err
		}
	}
	existing, err := s.Store.AllSubdomains(ctx)
	if err != nil {
		return 0, err
	}
	for _, d := range existing {
		if d.Name == name {
			return 0, ErrDuplicateSubdomain
		}
	}
	conflict, err := s.DNS.HasExactRecord(ctx, name)
	if err != nil {
		return 0, ErrDNSUnavailable
	}
	if conflict {
		return 0, ErrDNSConflict
	}
	id, err := s.Store.InsertSubdomainAtomic(ctx, uid, name, store.AuditEntry{Actor: &uid, Target: &uid, Action: "subdomain.reserve", ResourceType: "subdomain", SourceIP: ip})
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return 0, ErrDuplicateSubdomain
		}
		return 0, err
	}
	return id, nil
}
func (s *Service) ReleaseSubdomain(ctx context.Context, actor int64, admin bool, id int64, ip string) error {
	d, err := s.Store.Subdomain(ctx, id)
	if err != nil {
		return err
	}
	if !admin && d.UserID != actor {
		return ErrForbidden
	}
	action := "subdomain.release"
	if admin {
		action = "admin.subdomain.force_release"
	}
	if err = s.Store.DeleteSubdomainAtomic(ctx, id, d.Name, store.AuditEntry{Actor: &actor, Target: &d.UserID, Action: action, ResourceType: "subdomain", ResourceID: strconv.FormatInt(id, 10), SourceIP: ip}); err != nil {
		return err
	}
	return nil
}
func (s *Service) SetUserSuspended(ctx context.Context, actor, target int64, suspended bool, ip string) error {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	u, err := s.Store.UserByID(ctx, target)
	if err != nil {
		return err
	}
	if u.Role == "admin" && suspended {
		return errors.New("管理者アカウントは停止できません")
	}
	action := "admin.user.unsuspend"
	if suspended {
		action = "admin.user.suspend"
		keys, keyErr := s.Store.KeysByUser(ctx, target)
		if keyErr != nil {
			return keyErr
		}
		// Remove every possible authorization first. A later DB failure remains
		// fail closed because sish no longer has the user's managed files.
		for _, k := range keys {
			if err = s.Keys.Remove(k.UserID, k.ID); err != nil {
				return err
			}
		}
		if err = s.Store.SetUserStatusAtomic(ctx, target, "suspended", store.AuditEntry{Actor: &actor, Target: &target, Action: action, ResourceType: "user", ResourceID: strconv.FormatInt(target, 10), SourceIP: ip}); err != nil {
			return err
		}
	} else {
		if err = s.Store.SetUserStatusAtomic(ctx, target, "active", store.AuditEntry{Actor: &actor, Target: &target, Action: action, ResourceType: "user", ResourceID: strconv.FormatInt(target, 10), SourceIP: ip}); err != nil {
			return err
		}
		// pubkey reconciliation is transactionally queued; an immediate best-effort
		// pass reduces activation latency without changing the committed state.
		_ = s.syncLocked(ctx)
	}
	return nil
}

func (s *Service) audit(ctx context.Context, actor, target *int64, action, typ, rid, ip string) {
	if err := s.Store.Audit(ctx, actor, target, action, typ, rid, ip, "{}"); err != nil {
		logger := s.Logger
		if logger == nil {
			logger = slog.Default()
		}
		// Mutations are already committed at this point. Audit is explicitly
		// best-effort for the MVP, but failures are never silent.
		logger.Error("audit log write failed", "action", action, "resource_type", typ, "resource_id", rid, "error", err)
	}
}

func IsNotFound(err error) bool { return errors.Is(err, sql.ErrNoRows) }
