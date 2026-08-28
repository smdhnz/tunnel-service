export interface CurrentUser {
  Username: string; DisplayName: string; AvatarURL: string; Role: 'user' | 'admin';
}
export interface AdminUser {
  ID: number; DiscordID: string; Username: string; Email: string; AvatarURL: string;
  Role: 'user' | 'admin'; Status: string; CreatedAt: string;
  SSHKeyCount: number; SubdomainCount: number; TCPPortCount: number;
}
export interface SSHKey { ID: number; Owner?: string; Name: string; PublicKey?: string; Fingerprint: string; Enabled: boolean; CreatedAt: string }
export interface Subdomain { ID: number; Owner?: string; Name: string; DNSConflict?: string; CreatedAt: string }
export interface TCPPort { ID: number; Owner?: string; Port: number; CreatedAt: string }
export interface Audit { Action: string; SourceIP?: string; CreatedAt: string }
export interface ActiveTunnel {
  owner?: string; key_name?: string; protocol: string; hostname: string; source_ip: string;
  status?: string; port: number; connected_at: string;
}
export interface SecurityMetric { BucketStart: string; EventType: string; Count: number }
export interface Stats { Users: number; ActiveUsers: number; SSHKeys: number; Subdomains: number; TCPPorts: number; SuspendedUsers: number; ActiveTunnels: number }
export interface Pagination { Page: number; PreviousURL: string; NextURL: string }
export interface PageData {
  Title: string; Page: string; CSRF: string; Flash: string; Error: string; User: CurrentUser;
  TunnelDomain?: string; SSHHost?: string; ConnectCommand?: string; TCPConnectCommand?: string; SSHPort?: number;
  KeyCount?: number; SubdomainCount?: number; TCPPortCount?: number; FirstTCPPort?: number; ActiveTunnelCount?: number;
  Keys?: SSHKey[]; Subdomains?: Subdomain[]; TCPPorts?: TCPPort[]; Users?: AdminUser[]; Audit?: Audit[];
  ActiveTunnels?: ActiveTunnel[]; SecurityMetrics?: SecurityMetric[]; Stats?: Stats; Pagination?: Pagination;
  ActiveTunnelAvailable?: boolean;
}
export interface MutationResult { flash: string; error: string }
