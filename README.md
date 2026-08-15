# Tunnel Service

`sish` を使ったリバーストンネル基盤です。

SSH reverse forwarding を使って、ローカルのHTTPサービスをインターネットへ公開できます。

現在は、登録済みのSSH公開鍵を持つクライアントのみがトンネルを作成できます。

## Current Architecture

* VPS: KAGOYA CLOUD VPS
* OS: Ubuntu 24.04 LTS
* Container Runtime: Docker / Docker Compose
* Tunnel Server: sish
* DNS: Vercel DNS
* TLS: Let's Encrypt
* ACME Client: Certbot
* DNS-01 Automation: Vercel REST API
* SSH Authentication: Public Key Authentication

## Environment Variables

環境固有の値は `.env` で管理します。

例:

```env
TUNNEL_DOMAIN=example.com
SSH_HOST=ssh.example.com
VPS_IP=203.0.113.10

SISH_SSH_PORT=2222
SISH_HTTP_PORT=80
SISH_HTTPS_PORT=443

VERCEL_TOKEN=your_vercel_token
```

`.env` はGit管理しません。

リポジトリには `.env.example` のみコミットします。

## DNS

以下のDNSレコードを設定します。

```text
ssh.<your-domain>    A    <VPS IPv4>
*.<your-domain>      A    <VPS IPv4>
```

既存のVercelアプリ用サブドメインがある場合は、個別のCNAMEレコードでVercelへ向けます。

例:

```text
app.<your-domain>    CNAME    cname.vercel-dns-017.com.
```

## Tunnel Example

ローカルでWebサーバーを起動します。

```bash
python3 -m http.server 3000
```

登録済みのSSH鍵を使ってsishへ接続します。

```bash
ssh -i ~/.ssh/id_ed25519 \
  -p 2222 \
  -R test:80:localhost:3000 \
  ssh.<your-domain>
```

以下でアクセスできます。

```text
http://test.<your-domain>
https://test.<your-domain>
```

## SSH Authentication

sishへの接続はSSH公開鍵認証を必須にしています。

許可する公開鍵は `pubkeys/` 配下に配置します。

例:

```text
pubkeys/
└── user.pub
```

公開鍵ファイルの内容はOpenSSH形式です。

```text
ssh-ed25519 AAAA... user@example
```

登録済みの公開鍵を使用した接続は許可されます。

未登録鍵を使用した場合は、以下のように拒否されます。

```text
Permission denied (publickey).
```

## Ports

* `80/tcp`: HTTP
* `443/tcp`: HTTPS
* `2222/tcp`: sish SSH endpoint

## Directory Structure

```text
.
├── compose.yml
├── README.md
├── .gitignore
├── .env
├── .env.example
├── keys/
├── pubkeys/
├── ssl/
└── scripts/
    ├── certbot-auth.sh
    ├── certbot-cleanup.sh
    └── install-certbot-deploy.sh
```

## Docker Compose

現在の構成では、環境変数からポートやドメインを読み込みます。

主要なsish設定は以下です。

```yaml
command:
  - --ssh-address=:${SISH_SSH_PORT:-2222}
  - --http-address=:${SISH_HTTP_PORT:-80}
  - --https-address=:${SISH_HTTPS_PORT:-443}
  - --domain=${TUNNEL_DOMAIN}

  - --authentication=true
  - --authentication-keys-directory=/pubkeys
  - --private-keys-directory=/keys
  - --verify-dns=false
  - --bind-random-subdomains=false
  - --bind-random-ports=true

  - --https
  - --https-certificate-directory=/ssl
```

主要なvolumeは以下です。

```yaml
volumes:
  - ./keys:/keys
  - ./ssl:/ssl:ro
  - ./pubkeys:/pubkeys:ro
```

## SSH Host Keys

sish自身のSSHホスト鍵は `keys/` 配下へ永続化します。

これにより、Dockerコンテナを再作成してもSSH fingerprintが変わりません。

```text
keys/
└── ssh_key
```

`keys/` は秘密情報を含むためGit管理しません。

## TLS Certificate

Let's Encrypt のワイルドカード証明書を使用します。

```text
*.<your-domain>
```

Certbotによって生成された証明書は、sish用に以下へ配置します。

```text
ssl/
├── <your-domain>.crt
└── <your-domain>.key
```

sishは `ssl/` をread-onlyでマウントしてHTTPS通信を処理します。

## Certbot DNS-01 Automation

ワイルドカード証明書の取得・更新ではDNS-01 challengeを使用します。

DNSはVercelで管理しています。

Certbotの認証時に、Vercel REST APIを使って以下のTXTレコードを一時的に作成します。

```text
_acme-challenge.<your-domain>
```

処理の流れは以下です。

```text
Certbot
  |
  v
certbot-auth.sh
  |
  v
Vercel REST API
  |
  v
_acme-challenge TXT作成
  |
  v
DNS反映待機
  |
  v
Let's Encryptによる検証
  |
  v
証明書発行
  |
  v
certbot-cleanup.sh
  |
  v
TXT削除
```

## Certbot Hooks

### Authentication Hook

```text
scripts/certbot-auth.sh
```

Vercel APIを使って `_acme-challenge` TXTレコードを作成します。

このスクリプトは `.env` から以下を読み込みます。

```text
TUNNEL_DOMAIN
VERCEL_TOKEN
```

DNS反映待ちのため、現在は一定時間sleepしてからCertbotへ処理を戻します。

### Cleanup Hook

```text
scripts/certbot-cleanup.sh
```

認証後に、一時作成した `_acme-challenge` TXTレコードを削除します。

このスクリプトも `.env` から設定を読み込みます。

### Deploy Hook

Certbotの証明書更新成功後、sishへ新しい証明書を反映するdeploy hookを使います。

deploy hook本体はリポジトリ外の以下へ配置されます。

```text
/etc/letsencrypt/renewal-hooks/deploy/sish-cert.sh
```

このファイルは手動編集せず、リポジトリ内のインストーラーから生成します。

```bash
./scripts/install-certbot-deploy.sh
```

インストーラーは実行時の `.env` とリポジトリの絶対パスを使って、環境固有の値を埋め込んだdeploy hookを生成します。

生成されたdeploy hookは実行時に `.env` を参照しません。

deploy hookは証明書更新後に以下を実行します。

1. Certbotが管理する最新証明書を `ssl/` 配下へコピー
2. sishコンテナを再起動
3. 更新済み証明書をHTTPS endpointへ反映

環境再構築時は、Certbotと証明書をセットアップした後にインストーラーを再実行してください。

## Certbot Renewal

Certbotではmanual DNS challengeとhookを使って証明書を更新します。

例:

```bash
sudo certbot certonly \
  --manual \
  --preferred-challenges dns \
  --manual-auth-hook "$(pwd)/scripts/certbot-auth.sh" \
  --manual-cleanup-hook "$(pwd)/scripts/certbot-cleanup.sh" \
  -d "*.${TUNNEL_DOMAIN}"
```

初回セットアップ後は以下で自動更新可能か確認します。

```bash
sudo certbot renew --dry-run
```

成功時は以下のような結果になります。

```text
Congratulations, all simulated renewals succeeded
```

## Vercel API Token

CertbotのDNS-01自動化にはVercel API Tokenを使用します。

トークンは `.env` の以下の変数へ設定します。

```env
VERCEL_TOKEN=your_vercel_token
```

`.env` はGitへコミットしません。

## Git Ignore Policy

以下はGit管理しません。

* `.env`
* `ssl/`
* `keys/`
* `pubkeys/*.pub`
* SQLite database files
* Logs
* Temporary files
* Editor-specific files

特に以下は外部へ公開しないでください。

* Vercel API token
* TLS private key
* sish SSH host private key
* Application secrets
* Session secrets

SSH公開鍵そのものは秘密情報ではありませんが、`pubkeys/` は「誰がサービスを利用できるか」という認可設定でもあるため、実運用の `.pub` ファイルはGit管理しません。

## Security Status

現在、sishへの接続にはSSH公開鍵認証を必須にしています。

確認済みの挙動:

* 登録済みSSH公開鍵: 接続可能
* 未登録SSH公開鍵: 接続拒否
* HTTP reverse forwarding: 動作確認済み
* HTTPS reverse forwarding: 動作確認済み
* SSH host key persistence: 動作確認済み
* TLS certificate renewal dry-run: 成功
* Vercel DNS APIによるTXT作成・削除: 動作確認済み

一方で、まだPoC段階のため以下は未実装です。

* Web user authentication
* User / SSH key mapping
* Per-user subdomain authorization
* TCP port authorization
* Rate limiting
* Connection limits
* Abuse prevention
* Audit logging
* Tunnel lifecycle management
* Revocation workflow
* Admin GUI
* Security event monitoring

## Security Considerations

インターネットへSSH endpointを公開すると、自動スキャンや認証試行が発生します。

そのため、認証なしでsishを公開しないでください。

現在は以下を使用しています。

```text
--authentication=true
--authentication-keys-directory=/pubkeys
```

今後は単純な公開鍵ファイル方式から、Control Plane経由の認証・認可へ移行する予定です。

想定する構成:

```text
User
  |
  v
Web GUI
  |
  v
Control Plane
  |
  +--> User Account
  +--> SSH Public Keys
  +--> Subdomain Permissions
  +--> TCP Port Permissions
  |
  v
sish
```

## Planned Control Plane

GUI / Control Planeでは以下を管理する予定です。

* User accounts
* SSH public keys
* Reserved subdomains
* TCP ports
* Active tunnels
* Tunnel history
* Account settings
* Security events

## Planned GUI

想定する画面:

```text
Dashboard
├── Tunnels
├── Subdomains
├── TCP Ports
├── SSH Keys
├── Security
└── Account
```

## Future Features

### TCP Tunnel

HTTP/HTTPSだけでなく、任意TCPポートのreverse forwardingを提供します。

### Live Streaming

将来的には超低遅延ライブ配信を追加します。

想定用途:

```text
OBS
  |
  v
WHIP / WebRTC
  |
  v
Media Gateway
  |
  v
Browser
```

通常のHTTP/TCP tunnelとは別のMedia Gatewayとして設計する予定です。

## Next Steps

* Git initial commit
* Reproducible setup documentation
* Install / bootstrap scripts
* Control Plane / GUI
* User authentication
* SSH public key management
* Subdomain reservation
* TCP tunnel support
* Rate limiting
* Abuse prevention
* Audit logging
* Security hardening

