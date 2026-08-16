package web

import (
	"strconv"
	"time"

	"tunnel-control-plane/internal/model"
)

// pageDTO is the public contract for the management SPA. It deliberately does
// not embed Page or model types so additions to internal models cannot become
// API fields accidentally.
type pageDTO struct {
	Title, Page, CSRF, Flash, Error string
	User                            currentUserDTO
	TunnelDomain                    string              `json:",omitempty"`
	SSHHost                         string              `json:",omitempty"`
	ConnectCommand                  string              `json:",omitempty"`
	TCPConnectCommand               string              `json:",omitempty"`
	SSHPort                         int                 `json:",omitempty"`
	KeyCount                        int                 `json:",omitempty"`
	SubdomainCount                  int                 `json:",omitempty"`
	TCPPortCount                    int                 `json:",omitempty"`
	FirstTCPPort                    int                 `json:",omitempty"`
	ActiveTunnelCount               int                 `json:",omitempty"`
	Keys                            []keyDTO            `json:",omitempty"`
	Subdomains                      []subdomainDTO      `json:",omitempty"`
	TCPPorts                        []tcpPortDTO        `json:",omitempty"`
	Users                           []adminUserDTO      `json:",omitempty"`
	Audit                           []auditDTO          `json:",omitempty"`
	ActiveTunnels                   []activeTunnelDTO   `json:",omitempty"`
	SecurityMetrics                 []securityMetricDTO `json:",omitempty"`
	Stats                           *statsDTO           `json:",omitempty"`
	Pagination                      *paginationDTO      `json:",omitempty"`
	TunnelPagination                *paginationDTO      `json:",omitempty"`
	SecurityPagination              *paginationDTO      `json:",omitempty"`
	ActiveTunnelAvailable           *bool               `json:",omitempty"`
}

type currentUserDTO struct {
	Username, DisplayName, AvatarURL, Role string
}

type adminUserDTO struct {
	ID                                                  int64
	DiscordID, Username, Email, AvatarURL, Role, Status string
	CreatedAt                                           time.Time
	SSHKeyCount, SubdomainCount, TCPPortCount           int
}

type keyDTO struct {
	ID          int64
	Owner       string `json:",omitempty"`
	Name        string
	PublicKey   string `json:",omitempty"`
	Fingerprint string
	Enabled     bool
	CreatedAt   time.Time
}

type subdomainDTO struct {
	ID          int64
	Owner       string `json:",omitempty"`
	Name        string
	DNSConflict string `json:",omitempty"`
	CreatedAt   time.Time
}

type tcpPortDTO struct {
	ID        int64
	Owner     string `json:",omitempty"`
	Port      int
	CreatedAt time.Time
}

type auditDTO struct {
	Action    string
	SourceIP  string `json:",omitempty"`
	CreatedAt time.Time
}

type activeTunnelDTO struct {
	Owner       string    `json:"owner,omitempty"`
	KeyName     string    `json:"key_name,omitempty"`
	Protocol    string    `json:"protocol"`
	Hostname    string    `json:"hostname"`
	SourceIP    string    `json:"source_ip"`
	Status      string    `json:"status,omitempty"`
	TCPPort     int       `json:"port"`
	ConnectedAt time.Time `json:"connected_at"`
}

type securityMetricDTO struct {
	BucketStart time.Time
	EventType   string
	Count       int64
}

type statsDTO struct {
	Users, ActiveUsers, SSHKeys, Subdomains, TCPPorts, SuspendedUsers, ActiveTunnels int
}

type paginationDTO struct {
	Page                 int
	PreviousURL, NextURL string
	PageSizes            []pageSizeOptionDTO
}

type pageSizeOptionDTO struct {
	Size     int
	URL      string
	Selected bool
}

func newPageDTO(p Page) pageDTO {
	result := pageDTO{
		Title: p.Title,
		Page:  p.Page,
		CSRF:  p.CSRF,
		Flash: p.Flash,
		Error: p.Error,
		User: currentUserDTO{
			Username: p.User.Username, DisplayName: p.User.DisplayName,
			AvatarURL: p.User.AvatarURL, Role: p.User.Role,
		},
	}

	switch p.Page {
	case "dashboard":
		result.TunnelDomain, result.SSHHost, result.SSHPort = p.TunnelDomain, p.SSHHost, p.SSHPort
		result.ConnectCommand = p.ConnectCommand
		result.KeyCount, result.SubdomainCount, result.TCPPortCount = len(p.Keys), len(p.Subdomains), len(p.TCPPorts)
		result.ActiveTunnelCount = len(p.ActiveTunnels)
		result.ActiveTunnelAvailable = boolPointer(p.ActiveTunnelAvailable)
		result.Audit = auditDTOs(p.Audit, false)
		if len(p.TCPPorts) > 0 {
			result.FirstTCPPort = p.TCPPorts[0].Port
			result.TCPConnectCommand = "ssh -N -p " + strconv.Itoa(p.SSHPort) + " -R " + strconv.Itoa(p.TCPPorts[0].Port) + ":127.0.0.1:LOCAL_PORT " + p.SSHHost
		} else {
			result.TCPConnectCommand = "ssh -N -p " + strconv.Itoa(p.SSHPort) + " -R PUBLIC_PORT:127.0.0.1:LOCAL_PORT " + p.SSHHost
		}
	case "keys":
		result.Keys = keyDTOs(p.Keys, false)
	case "subdomains":
		result.TunnelDomain = p.TunnelDomain
		result.Subdomains = subdomainDTOs(p.Subdomains, false)
	case "tcp-ports":
		result.SSHHost, result.SSHPort = p.SSHHost, p.SSHPort
		result.TCPPorts = tcpPortDTOs(p.TCPPorts, false)
	case "tunnels":
		result.ActiveTunnels = activeTunnelDTOs(p.ActiveTunnels, false)
		result.ActiveTunnelAvailable = boolPointer(p.ActiveTunnelAvailable)
	case "admin-home":
		result.Stats = statsDTOFrom(p.Stats)
		result.Audit = auditDTOs(p.Audit, true)
	case "admin-users":
		result.Users = adminUserDTOs(p.Users)
		result.Pagination = paginationDTOFrom(p.Pagination)
	case "admin-keys":
		result.Keys = keyDTOs(p.Keys, true)
		result.Pagination = paginationDTOFrom(p.Pagination)
	case "admin-subdomains":
		result.TunnelDomain = p.TunnelDomain
		result.Subdomains = subdomainDTOs(p.Subdomains, true)
		result.Pagination = paginationDTOFrom(p.Pagination)
	case "admin-tcp-ports":
		result.TCPPorts = tcpPortDTOs(p.TCPPorts, true)
		result.Pagination = paginationDTOFrom(p.Pagination)
	case "admin-tunnels":
		result.ActiveTunnels = activeTunnelDTOs(p.ActiveTunnels, true)
		result.SecurityMetrics = securityMetricDTOs(p.SecurityMetrics)
		result.ActiveTunnelAvailable = boolPointer(p.ActiveTunnelAvailable)
		result.TunnelPagination = paginationDTOFrom(p.TunnelPagination)
		result.SecurityPagination = paginationDTOFrom(p.SecurityPagination)
	}
	return result
}

func keyDTOs(values []model.SSHKey, admin bool) []keyDTO {
	result := make([]keyDTO, 0, len(values))
	for _, value := range values {
		item := keyDTO{ID: value.ID, Name: value.Name, Fingerprint: value.Fingerprint, Enabled: value.Enabled, CreatedAt: value.CreatedAt}
		if admin {
			item.Owner = value.Owner
		} else {
			item.PublicKey = value.PublicKey
			if len(item.PublicKey) > 42 {
				item.PublicKey = item.PublicKey[:42] + "…"
			}
		}
		result = append(result, item)
	}
	return result
}

func subdomainDTOs(values []model.Subdomain, admin bool) []subdomainDTO {
	result := make([]subdomainDTO, 0, len(values))
	for _, value := range values {
		item := subdomainDTO{ID: value.ID, Name: value.Name, CreatedAt: value.CreatedAt}
		if admin {
			item.Owner, item.DNSConflict = value.Owner, value.DNSConflict
		}
		result = append(result, item)
	}
	return result
}

func tcpPortDTOs(values []model.TCPPort, admin bool) []tcpPortDTO {
	result := make([]tcpPortDTO, 0, len(values))
	for _, value := range values {
		item := tcpPortDTO{ID: value.ID, Port: value.Port, CreatedAt: value.CreatedAt}
		if admin {
			item.Owner = value.Owner
		}
		result = append(result, item)
	}
	return result
}

func adminUserDTOs(values []model.User) []adminUserDTO {
	result := make([]adminUserDTO, 0, len(values))
	for _, value := range values {
		result = append(result, adminUserDTO{ID: value.ID, DiscordID: value.DiscordID, Username: value.Username, Email: value.Email, AvatarURL: value.AvatarURL, Role: value.Role, Status: value.Status, CreatedAt: value.CreatedAt, SSHKeyCount: value.SSHKeyCount, SubdomainCount: value.SubdomainCount, TCPPortCount: value.TCPPortCount})
	}
	return result
}

func auditDTOs(values []model.AuditLog, includeSource bool) []auditDTO {
	result := make([]auditDTO, 0, len(values))
	for _, value := range values {
		item := auditDTO{Action: value.Action, CreatedAt: value.CreatedAt}
		if includeSource {
			item.SourceIP = value.SourceIP
		}
		result = append(result, item)
	}
	return result
}

func activeTunnelDTOs(values []model.ActiveTunnel, admin bool) []activeTunnelDTO {
	result := make([]activeTunnelDTO, 0, len(values))
	for _, value := range values {
		item := activeTunnelDTO{KeyName: value.KeyName, Protocol: value.Protocol, Hostname: value.Hostname, SourceIP: value.SourceIP, Status: value.Status, TCPPort: value.TCPPort, ConnectedAt: value.ConnectedAt}
		if admin {
			item.Owner = value.Owner
		}
		result = append(result, item)
	}
	return result
}

func securityMetricDTOs(values []model.SecurityMetric) []securityMetricDTO {
	result := make([]securityMetricDTO, 0, len(values))
	for _, value := range values {
		result = append(result, securityMetricDTO{BucketStart: value.BucketStart, EventType: value.EventType, Count: value.Count})
	}
	return result
}

func statsDTOFrom(value model.Stats) *statsDTO {
	return &statsDTO{Users: value.Users, ActiveUsers: value.ActiveUsers, SSHKeys: value.SSHKeys, Subdomains: value.Subdomains, TCPPorts: value.TCPPorts, SuspendedUsers: value.SuspendedUsers, ActiveTunnels: value.ActiveTunnels}
}

func paginationDTOFrom(value Pagination) *paginationDTO {
	result := &paginationDTO{Page: value.Page, PreviousURL: value.PreviousURL, NextURL: value.NextURL, PageSizes: make([]pageSizeOptionDTO, 0, len(value.PageSizes))}
	for _, option := range value.PageSizes {
		result.PageSizes = append(result.PageSizes, pageSizeOptionDTO{Size: option.Size, URL: option.URL, Selected: option.Selected})
	}
	return result
}

func boolPointer(value bool) *bool { return &value }
