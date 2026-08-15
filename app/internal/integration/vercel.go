package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var ErrDNSCheckUnavailable = errors.New("DNS conflict check unavailable")

type DNSChecker interface {
	HasExactRecord(context.Context, string) (bool, error)
}

type VercelDNS struct {
	Token, Domain, TeamID string
	Client                *http.Client
	BaseURL               string
}
type dnsResponse struct {
	Records []struct {
		Name string `json:"name"`
	} `json:"records"`
	Pagination *struct {
		Next json.RawMessage `json:"next"`
	} `json:"pagination"`
}

func (v *VercelDNS) HasExactRecord(ctx context.Context, label string) (bool, error) {
	if v.Token == "" {
		return false, ErrDNSCheckUnavailable
	}
	client := v.Client
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}
	base := v.BaseURL
	if base == "" {
		base = "https://api.vercel.com"
	}
	label = strings.ToLower(strings.TrimSuffix(label, "."))
	fqdn := label + "." + strings.ToLower(strings.TrimSuffix(v.Domain, "."))
	until := ""
	seen := map[string]struct{}{}
	for page := 0; page < 100; page++ {
		u := fmt.Sprintf("%s/v4/domains/%s/records?limit=100", strings.TrimRight(base, "/"), url.PathEscape(v.Domain))
		if v.TeamID != "" {
			u += "&teamId=" + url.QueryEscape(v.TeamID)
		}
		if until != "" {
			u += "&until=" + url.QueryEscape(until)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return false, ErrDNSCheckUnavailable
		}
		req.Header.Set("Authorization", "Bearer "+v.Token)
		res, err := client.Do(req)
		if err != nil {
			return false, fmt.Errorf("%w: request failed", ErrDNSCheckUnavailable)
		}
		var data dnsResponse
		decodeErr := json.NewDecoder(io.LimitReader(res.Body, 2<<20)).Decode(&data)
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return false, fmt.Errorf("%w: status %d", ErrDNSCheckUnavailable, res.StatusCode)
		}
		if decodeErr != nil {
			return false, fmt.Errorf("%w: invalid response", ErrDNSCheckUnavailable)
		}
		for _, r := range data.Records {
			name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.Name), "."))
			if strings.Contains(name, "*") {
				continue
			}
			if name == label || name == fqdn {
				return true, nil
			}
		}
		if data.Pagination == nil {
			return false, fmt.Errorf("%w: pagination missing", ErrDNSCheckUnavailable)
		}
		next, done, cursorErr := paginationValue(data.Pagination.Next)
		if cursorErr != nil {
			return false, fmt.Errorf("%w: %v", ErrDNSCheckUnavailable, cursorErr)
		}
		if done {
			return false, nil
		}
		if _, repeated := seen[next]; repeated || next == until {
			return false, fmt.Errorf("%w: pagination cursor repeated", ErrDNSCheckUnavailable)
		}
		seen[next] = struct{}{}
		until = next
	}
	return false, fmt.Errorf("%w: pagination limit exceeded", ErrDNSCheckUnavailable)
}

func paginationValue(raw json.RawMessage) (value string, done bool, err error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return "", false, errors.New("pagination cursor missing")
	}
	if bytes.Equal(raw, []byte("null")) {
		return "", true, nil
	}
	if raw[0] == '"' {
		if json.Unmarshal(raw, &value) != nil || value == "" {
			return "", false, errors.New("invalid pagination cursor")
		}
		return value, false, nil
	}
	var number json.Number
	if json.Unmarshal(raw, &number) != nil || number.String() == "" {
		return "", false, errors.New("invalid pagination cursor")
	}
	return number.String(), false, nil
}
