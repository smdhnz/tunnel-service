package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"tunnel-control-plane/internal/model"
)

type SishClient struct {
	BaseURL, TokenFile string
	Client             *http.Client
}

type disconnectRequest struct {
	KeyID      int64  `json:"key_id,omitempty"`
	UserID     int64  `json:"user_id,omitempty"`
	Generation int64  `json:"generation"`
	Hostname   string `json:"hostname,omitempty"`
	TunnelID   string `json:"tunnel_id,omitempty"`
}

func NewSishClient(baseURL, tokenFile string) (*SishClient, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "http" || !isLoopback(u.Hostname()) {
		return nil, errors.New("SISH_MANAGEMENT_URL must be an HTTP loopback URL")
	}
	return &SishClient{BaseURL: strings.TrimRight(baseURL, "/"), TokenFile: tokenFile, Client: &http.Client{Timeout: 3 * time.Second}}, nil
}
func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())
}
func (c *SishClient) token() (string, error) {
	b, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(b))
	if len(v) < 32 {
		return "", errors.New("management token must contain at least 32 characters")
	}
	return v, nil
}
func (c *SishClient) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return err
	}
	token, err := c.token()
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("sish management status %d", res.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(out)
	}
	return nil
}
func (c *SishClient) DisconnectKey(ctx context.Context, id, generation int64) error {
	return c.do(ctx, http.MethodPost, "/v1/disconnect", disconnectRequest{KeyID: id, Generation: generation}, nil)
}
func (c *SishClient) DisconnectUser(ctx context.Context, id, generation int64) error {
	return c.do(ctx, http.MethodPost, "/v1/disconnect", disconnectRequest{UserID: id, Generation: generation}, nil)
}
func (c *SishClient) DisconnectHost(ctx context.Context, host string, generation int64) error {
	return c.do(ctx, http.MethodPost, "/v1/disconnect", disconnectRequest{Hostname: host, Generation: generation}, nil)
}
func (c *SishClient) Active(ctx context.Context) (model.TunnelSnapshot, error) {
	var v model.TunnelSnapshot
	err := c.do(ctx, http.MethodGet, "/v1/tunnels", nil, &v)
	return v, err
}
func (c *SishClient) Metrics(ctx context.Context) (map[string]int64, error) {
	var v map[string]int64
	err := c.do(ctx, http.MethodGet, "/v1/metrics", nil, &v)
	return v, err
}
