package model

import "time"

type User struct {
	ID                                                               int64
	DiscordID, Username, DisplayName, Email, AvatarURL, Role, Status string
	CreatedAt, UpdatedAt                                             time.Time
	SSHKeyCount, SubdomainCount                                      int
}

type SSHKey struct {
	ID, UserID                          int64
	Owner, Name, PublicKey, Fingerprint string
	Enabled                             bool
	CreatedAt, UpdatedAt                time.Time
}

type Subdomain struct {
	ID, UserID                       int64
	Owner, Name, Status, DNSConflict string
	CreatedAt, UpdatedAt             time.Time
}

type AuditLog struct {
	ID                                                   int64
	ActorUserID, TargetUserID                            *int64
	Action, ResourceType, ResourceID, SourceIP, Metadata string
	CreatedAt                                            time.Time
}

type ActiveTunnel struct {
	ID             string    `json:"id"`
	UserID         int64     `json:"user_id"`
	SSHKeyID       int64     `json:"key_id"`
	Owner          string    `json:"owner,omitempty"`
	KeyName        string    `json:"key_name,omitempty"`
	Protocol       string    `json:"protocol"`
	Hostname       string    `json:"hostname"`
	SourceIP       string    `json:"source_ip"`
	Status         string    `json:"status,omitempty"`
	TCPPort        int       `json:"port"`
	Generation     int64     `json:"generation"`
	EventSequence  int64     `json:"sequence,omitempty"`
	ConnectedAt    time.Time `json:"connected_at"`
	DisconnectedAt time.Time `json:"disconnected_at,omitempty"`
}

type TunnelSnapshot struct {
	SourceID string         `json:"source_id"`
	Sequence int64          `json:"sequence"`
	Tunnels  []ActiveTunnel `json:"tunnels"`
}

type TunnelSyncState struct {
	Available     bool
	LastSequence  int64
	LastSuccessAt time.Time
	LastErrorAt   time.Time
}

type SecurityMetric struct {
	BucketStart time.Time
	EventType   string
	Count       int64
}

type OutboxItem struct {
	ID                       int64
	Kind, DedupeKey, Payload string
	Attempts                 int
	AvailableAt              time.Time
}

type Stats struct{ Users, ActiveUsers, SSHKeys, Subdomains, SuspendedUsers, ActiveTunnels int }
