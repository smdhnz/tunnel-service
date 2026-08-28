package web

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"tunnel-control-plane/internal/model"
)

func dtoJSONMap(t *testing.T, page Page) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(newPageDTO(page))
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func assertOnlyKeys(t *testing.T, value map[string]any, keys ...string) {
	t.Helper()
	allowed := make(map[string]bool, len(keys))
	for _, key := range keys {
		allowed[key] = true
	}
	for key := range value {
		if !allowed[key] {
			t.Errorf("unexpected JSON field %q in %#v", key, value)
		}
	}
	for _, key := range keys {
		if _, ok := value[key]; !ok {
			t.Errorf("required JSON field %q is missing from %#v", key, value)
		}
	}
}

func TestPageDTOUserKeyContract(t *testing.T) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	page := Page{
		Title: "SSH公開鍵", Page: "keys", CSRF: "csrf", User: &model.User{ID: 99, DiscordID: "private", Username: "user", DisplayName: "User", Email: "private@example.test", AvatarURL: "avatar", Role: "user", Status: "active"},
		Keys: []model.SSHKey{{ID: 10, UserID: 99, Owner: "not-needed", Name: "work", PublicKey: strings.Repeat("a", 60), Fingerprint: "SHA256:test", Enabled: true, CreatedAt: created, UpdatedAt: created.Add(time.Hour)}},
	}
	result := dtoJSONMap(t, page)
	assertOnlyKeys(t, result, "Title", "Page", "CSRF", "Flash", "Error", "User", "Keys")
	assertOnlyKeys(t, result["User"].(map[string]any), "Username", "DisplayName", "AvatarURL", "Role")
	key := result["Keys"].([]any)[0].(map[string]any)
	assertOnlyKeys(t, key, "ID", "Name", "PublicKey", "Fingerprint", "Enabled", "CreatedAt")
	if preview := key["PublicKey"].(string); len([]byte(preview)) != 45 || !strings.HasSuffix(preview, "…") {
		t.Fatalf("unexpected preview %q", preview)
	}
}

func TestPageDTOAdminContractsDoNotExposeInternalModelFields(t *testing.T) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	user := &model.User{ID: 1, Username: "admin", DisplayName: "Admin", AvatarURL: "avatar", Role: "admin"}

	keys := dtoJSONMap(t, Page{Title: "keys", Page: "admin-keys", CSRF: "csrf", User: user, Keys: []model.SSHKey{{ID: 2, UserID: 4, Owner: "owner", Name: "key", PublicKey: "must-not-leak", Fingerprint: "fp", Enabled: true, CreatedAt: created, UpdatedAt: created}}, Pagination: Pagination{Page: 1}})
	key := keys["Keys"].([]any)[0].(map[string]any)
	assertOnlyKeys(t, key, "ID", "Owner", "Name", "Fingerprint", "Enabled", "CreatedAt")

	tunnels := dtoJSONMap(t, Page{Title: "tunnels", Page: "admin-tunnels", CSRF: "csrf", User: user, ActiveTunnels: []model.ActiveTunnel{{ID: "internal", UserID: 4, SSHKeyID: 5, Owner: "owner", KeyName: "key", Protocol: "http", Hostname: "app.example", SourceIP: "127.0.0.1", Status: "active", TCPPort: 12345, Generation: 8, EventSequence: 9, ConnectedAt: created, DisconnectedAt: created.Add(time.Hour)}}, Pagination: Pagination{Page: 1}})
	tunnel := tunnels["ActiveTunnels"].([]any)[0].(map[string]any)
	assertOnlyKeys(t, tunnel, "owner", "key_name", "protocol", "hostname", "source_ip", "status", "port", "connected_at")
	if _, ok := tunnels["SecurityMetrics"]; ok {
		t.Fatal("tunnel page includes security metrics")
	}
	security := dtoJSONMap(t, Page{Title: "security", Page: "admin-security", CSRF: "csrf", User: user, SecurityMetrics: []model.SecurityMetric{{BucketStart: created, EventType: "rate_limited", Count: 2}}, Pagination: Pagination{Page: 1}})
	if _, ok := security["ActiveTunnels"]; ok {
		t.Fatal("security page includes active tunnels")
	}
}

func TestPageDTOAdminUserKeepsOnlyDisplayedAndActionFields(t *testing.T) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	page := Page{Title: "users", Page: "admin-users", CSRF: "csrf", User: &model.User{Username: "admin", DisplayName: "Admin", Role: "admin"}, Users: []model.User{{ID: 2, DiscordID: "discord", Username: "target", DisplayName: "not-displayed", Email: "mail@example.test", AvatarURL: "avatar", Role: "user", Status: "active", CreatedAt: created, UpdatedAt: created.Add(time.Hour), SSHKeyCount: 1, SubdomainCount: 2, TCPPortCount: 3}}, Pagination: Pagination{Page: 1}}
	result := dtoJSONMap(t, page)
	user := result["Users"].([]any)[0].(map[string]any)
	assertOnlyKeys(t, user, "ID", "DiscordID", "Username", "Email", "AvatarURL", "Role", "Status", "CreatedAt", "SSHKeyCount", "SubdomainCount", "TCPPortCount")
}
