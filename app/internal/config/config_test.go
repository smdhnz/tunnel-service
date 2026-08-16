package config

import (
	"strings"
	"testing"
)

func setRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("TUNNEL_DOMAIN", "example.test")
	t.Setenv("SSH_HOST", "ssh.example.test")
	t.Setenv("CONTROL_PLANE_SUBDOMAIN", "tunnel")
	t.Setenv("DISCORD_CLIENT_ID", "id")
	t.Setenv("DISCORD_CLIENT_SECRET", "secret")
	t.Setenv("SESSION_SECRET", strings.Repeat("s", 32))
	t.Setenv("CONTROL_PLANE_HOST", "")
}

func TestControlPlaneSubdomainRequiredAndValidated(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("COOKIE_SECURE", "true")
	t.Setenv("DISCORD_REDIRECT_URI", "https://tunnel.example.test/auth/callback")
	for _, value := range []string{"", "bad_name", "-bad"} {
		t.Setenv("CONTROL_PLANE_SUBDOMAIN", value)
		if _, err := Load(); err == nil {
			t.Fatalf("invalid subdomain %q accepted", value)
		}
	}
}

func TestCookieSecurityConfiguration(t *testing.T) {
	t.Run("localhost development", func(t *testing.T) {
		setRequiredEnv(t)
		t.Setenv("COOKIE_SECURE", "false")
		t.Setenv("DISCORD_REDIRECT_URI", "http://localhost:8080/auth/callback")
		if _, err := Load(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("insecure production rejected", func(t *testing.T) {
		setRequiredEnv(t)
		t.Setenv("COOKIE_SECURE", "false")
		t.Setenv("DISCORD_REDIRECT_URI", "http://control.example.test/auth/callback")
		if _, err := Load(); err == nil {
			t.Fatal("insecure non-localhost configuration accepted")
		}
	})
	t.Run("secure host mismatch rejected", func(t *testing.T) {
		setRequiredEnv(t)
		t.Setenv("COOKIE_SECURE", "true")
		t.Setenv("CONTROL_PLANE_HOST", "other.example.test")
		t.Setenv("DISCORD_REDIRECT_URI", "https://control.example.test/auth/callback")
		if _, err := Load(); err == nil {
			t.Fatal("redirect and public host mismatch accepted")
		}
	})
}
