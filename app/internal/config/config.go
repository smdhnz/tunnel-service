package config

import (
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Addr, InternalAddr, PublicHost, DatabasePath, PubKeysDir      string
	InternalTokenFile, SISHManagementURL, SISHManagementTokenFile string
	TunnelDomain, SSHHost                                         string
	SISHSSHPort                                                   int
	DiscordClientID, DiscordClientSecret, DiscordRedirectURI      string
	SessionSecret                                                 string
	CookieSecure                                                  bool
	AdminDiscordIDs                                               map[string]bool
	VercelToken, VercelTeamID                                     string
}

func Load() (Config, error) {
	port, err := strconv.Atoi(env("SISH_SSH_PORT", "2222"))
	if err != nil {
		return Config{}, errors.New("SISH_SSH_PORT must be numeric")
	}
	cookieSecure, err := strconv.ParseBool(env("COOKIE_SECURE", "false"))
	if err != nil {
		return Config{}, errors.New("COOKIE_SECURE must be true or false")
	}
	c := Config{
		Addr: env("CONTROL_PLANE_ADDR", ":8080"), InternalAddr: env("CONTROL_PLANE_INTERNAL_ADDR", "127.0.0.1:8081"), PublicHost: strings.TrimSpace(os.Getenv("CONTROL_PLANE_HOST")), DatabasePath: env("DATABASE_PATH", "../data/control-plane.db"), PubKeysDir: env("PUBKEYS_DIR", "../pubkeys"),
		InternalTokenFile: env("CONTROL_PLANE_INTERNAL_TOKEN_FILE", "../secrets/control-plane-internal-token"), SISHManagementURL: env("SISH_MANAGEMENT_URL", "http://127.0.0.1:8082"), SISHManagementTokenFile: env("SISH_MANAGEMENT_TOKEN_FILE", "../secrets/sish-management-token"),
		TunnelDomain: strings.TrimSpace(os.Getenv("TUNNEL_DOMAIN")), SSHHost: strings.TrimSpace(os.Getenv("SSH_HOST")), SISHSSHPort: port,
		DiscordClientID: os.Getenv("DISCORD_CLIENT_ID"), DiscordClientSecret: secret("DISCORD_CLIENT_SECRET"), DiscordRedirectURI: os.Getenv("DISCORD_REDIRECT_URI"),
		SessionSecret: secret("SESSION_SECRET"), CookieSecure: cookieSecure,
		AdminDiscordIDs: csvSet(os.Getenv("ADMIN_DISCORD_IDS")), VercelToken: secret("VERCEL_TOKEN"), VercelTeamID: os.Getenv("VERCEL_TEAM_ID"),
	}
	if c.TunnelDomain == "" || c.SSHHost == "" {
		return Config{}, errors.New("TUNNEL_DOMAIN and SSH_HOST are required")
	}
	if c.DiscordClientID == "" || c.DiscordClientSecret == "" || c.DiscordRedirectURI == "" {
		return Config{}, errors.New("Discord OAuth configuration is required")
	}
	if len(c.SessionSecret) < 32 {
		return Config{}, errors.New("SESSION_SECRET or SESSION_SECRET_FILE must contain at least 32 characters")
	}
	if !loopbackAddr(c.InternalAddr) {
		return Config{}, errors.New("CONTROL_PLANE_INTERNAL_ADDR must be loopback-only")
	}
	redirect, err := url.Parse(c.DiscordRedirectURI)
	if err != nil || redirect.Hostname() == "" || redirect.Path == "" {
		return Config{}, errors.New("DISCORD_REDIRECT_URI must be an absolute callback URL")
	}
	if c.CookieSecure {
		if !strings.EqualFold(redirect.Scheme, "https") {
			return Config{}, errors.New("COOKIE_SECURE=true requires an HTTPS DISCORD_REDIRECT_URI")
		}
	} else if !strings.EqualFold(redirect.Scheme, "http") || !isLoopbackHost(redirect.Hostname()) {
		return Config{}, errors.New("COOKIE_SECURE=false is allowed only with an HTTP localhost redirect URI")
	}
	if c.PublicHost != "" {
		publicHost := c.PublicHost
		if host, _, splitErr := net.SplitHostPort(publicHost); splitErr == nil {
			publicHost = host
		}
		publicHost = strings.TrimSuffix(publicHost, ".")
		if !strings.EqualFold(publicHost, strings.TrimSuffix(redirect.Hostname(), ".")) {
			return Config{}, errors.New("CONTROL_PLANE_HOST must match DISCORD_REDIRECT_URI host")
		}
		if !c.CookieSecure && !isLoopbackHost(publicHost) {
			return Config{}, errors.New("COOKIE_SECURE=false is allowed only for localhost")
		}
	}
	return c, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
func loopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	return err == nil && isLoopbackHost(host)
}
func secret(k string) string {
	if file := strings.TrimSpace(os.Getenv(k + "_FILE")); file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	return os.Getenv(k)
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func csvSet(v string) map[string]bool {
	m := map[string]bool{}
	for _, x := range strings.Split(v, ",") {
		if x = strings.TrimSpace(x); x != "" {
			m[x] = true
		}
	}
	return m
}
