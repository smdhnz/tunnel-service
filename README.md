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
TUNNEL_DOMAIN=fumiya.dev
SSH_HOST=ssh.fumiya.dev
CONTROL_PLANE_HOST=console.fumiya.dev

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
  - --ssh-address=:2222
  - --http-address=:80
  - --https-address=:443
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

Control Planeとrepo内sish hardening patchで以下を追加しています。

* Discord Web user authentication、User / SSH key mapping、revocation workflow
* 予約所有者・有効鍵・active userをbind時に照合するper-user subdomain authorization
* Active tunnel lifecycle、user/admin live UI、鍵・ユーザー・hostname単位の強制切断
* Subdomain予約・Vercel DNS競合防止、transactional audit/outbox
* bounded per-IP rate/connection limit、temporary block、unknown-host lightweight 404
* 404とは分離した分単位の集約security telemetry

TCP tunnelは有効ユーザーの有効鍵かつ明示的な1〜65535番portだけを認可します。TCP portのユーザー別予約台帳はまだ提供していないため、HTTP/HTTPS subdomain認可より粒度が粗い点に注意してください。

## Security Considerations

インターネットへSSH endpointを公開すると、自動スキャンや認証試行が発生します。

そのため、認証なしでsishを公開しないでください。

現在は以下を使用しています。

```text
--authentication=true
--authentication-keys-directory=/pubkeys
```

SSHログイン自体は公開鍵directoryを維持し、各remote-forward requestはControl Planeのloopback authorization APIでも検証します。Control Planeのtimeout、エラー、denyは `required` modeでfail closedです。

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

## Control Plane MVP

`app/` に単一のGo applicationとして実装しています。

* Discord OAuth2 login（state検証、一回限りstate、session rotation）
* SQLite user / session / SSH key / subdomain / audit log管理
* OpenSSH公開鍵検証、fingerprint・重複検査
* `pubkeys/control-plane-<user-id>-<key-id>.pub` へのatomic反映（予約prefixにより既存手動鍵と分離）
* Vercel DNS APIのread-only exact record競合検査（障害時fail closed）
* User dashboard / SSH Keys / Subdomains
* Admin dashboard / Users / SSH Keys / Subdomains / Active Tunnels / Security telemetry
* CSRF、server-side authorization、security headers、CSP、body size・rate制限
* `active_tunnels`、集約`security_telemetry`、transactional `outbox`

内部は `config / store / service / integration / web` に分離しています。migrationは起動時に適用し、SQLiteではWAL、busy timeout、foreign keysを有効化します。鍵・subdomain・user状態のmutation、audit、outbox enqueueは同じSQLite transactionで確定します。filesystem失効とsish切断は即時実行に加え、idempotentなoutbox workerが指数backoff（最大5分）で永続retryします。起動後はsishのsequence付きregistry snapshotを5秒間隔で同期します。callbackとsnapshotはevent ID/sequenceで冪等化され、古いsnapshotは拒否します。management API障害時は接続を削除せず `stale`、失効要求中は `disconnecting` と表示し、sishからdisconnect確認後だけ `disconnected` にします。

### Local development

GoをインストールしたWSLではDockerなしで起動できます。

```bash
cp .env.example .env
# .envへDiscord OAuth設定、SESSION_SECRET等を設定
cd app
set -a; source ../.env; set +a
go run ./cmd/control-plane
```

ローカルHTTPでは `COOKIE_SECURE=false` を使用できますが、redirect URIのhostは `localhost` またはloopback addressに限定されます。本番は `COOKIE_SECURE=true` とHTTPS redirect URIが必須で、session/state cookieは `__Host-` prefix、`Path=/`、host-only、Secure、HttpOnlyになります。`CONTROL_PLANE_HOST` を設定した場合はredirect URIのhostと一致させてください。

Docker Composeでは、先にbind mount先をdeploy user所有で作成してから起動します。Composeは存在しないdirectoryをroot所有で暗黙作成せずfail fastします。

```bash
install -d -m 0750 data pubkeys keys ssl secrets
# sishとControl Planeは同じ非root UID/GIDで動作する。値は.envと一致させる。
chown -R "${CONTROL_PLANE_UID:-1000}:${CONTROL_PLANE_GID:-1000}" data pubkeys keys ssl secrets
umask 077
openssl rand -base64 48 > secrets/control-plane-internal-token
openssl rand -base64 48 > secrets/sish-management-token
printf '%s' "$DISCORD_CLIENT_SECRET" > secrets/discord-client-secret
openssl rand -base64 48 > secrets/session-secret
printf '%s' "$VERCEL_TOKEN" > secrets/vercel-token
chmod 0400 secrets/*
# 1000:1000以外で動かす場合は.envのUID/GIDを `id -u` / `id -g` に合わせる
# 既存証明書は .crt=0644 / .key=0640、keys/は上記UID/GID所有にする
find ssl -type f -name '*.crt' -exec chmod 0644 {} +
find ssl -type f -name '*.key' -exec chmod 0640 {} +
docker compose up --build -d
```

Control Planeは `data/` と `pubkeys/` へ書き込み、sishは `keys/` へhost keyを書き込みます。両containerの `CONTROL_PLANE_UID` / `CONTROL_PLANE_GID` はbind mountとsecret fileを所有するdeploy userのIDへ合わせてください。sishは従来どおり `pubkeys/` と `ssl/` をread-only mountし、tokenは0400、TLS秘密鍵は0640で同UID/GIDだけが読めます。両containerはread-only root filesystem、全capability drop、`no-new-privileges`で動作し、sishだけが80/443 bind用の`NET_BIND_SERVICE`を持ちます。Certbot deploy hook installerはこのUID/GIDとmodeを生成hookへ固定します。`control-plane-` prefixはControl Plane管理用に予約し、このprefixがない既存手動鍵（数字形式のファイル名を含む）は削除・上書きしません。

### Secret isolation

Composeは `.env` をinterpolationへ使用しますが、secret値をcontainer環境変数やcommand lineへ展開しません。`secrets/` のread-only fileを必要なcontainerだけへmountします。sishが受け取るのはControl Plane internal API tokenとsish management API tokenだけで、Discord secret、session secret、Vercel tokenは受け取りません。Control PlaneのVercel integrationはDNS record一覧のGETだけを実装し、作成・更新・削除を行いません。Certbot scriptsの既存DNS-01更新処理とは分離されています。

### Internet scans and unknown hosts

未登録hostnameはsishで対応するtunnelを探索後、backendへproxyせずbodyなし404で終了します。unknown-host 404は1件ずつapplication log/audit DBへ書かず、`unknown_host` counterとして分単位で集約します。sishは`RemoteAddr`だけをIP判定に使い、未設定のproxy headerを信頼しません。per-IP stateは最大10,000件です。HTTP/HTTPS/TCP/SSHはprotocol解析前のaccept段階で接続数を制限（HTTP/TCP 50、SSH 20）し、HTTP serverは5秒のReadHeaderTimeoutを設定します。request bucketは120 burst・毎秒2回復、accept bucketは60 burst・毎秒1回復で、違反継続時は5分blockします。Control Planeにもgeneral/login/mutation別のbounded limiterがあります。

### sish patchと認可mode

upstreamの `authentication-key-request-url` はSSH鍵のログイン可否だけを受け取り、requested bindを受け取りません。そのため `sish/Dockerfile` はupstream commit `9609e83bb87aa7c65b14a67e84738c9ad13cd3ca` を固定取得し、`sish/patches/control-plane.patch` を `git apply --check` 後にbuildします。upstream全体はvendorしません。

* `required`（default）: callback deny・timeout・error、未移行manual key、所有外hostnameをbind拒否。random subdomain fallbackも禁止
* `audit`: callback結果を記録しつつ移行中のbindを継続。セキュリティ境界として使用しない

#### 既存manual keyからの無停止移行

1. `SISH_CONTROL_PLANE_MODE=audit` でpatched sishを起動する
2. 既存利用者をDiscord loginさせ、manual keyと利用hostnameをControl Planeへ登録・予約する
3. AdminのActive Tunnelsとsecurity telemetryでdeny候補がないことを確認する
4. `.env` を `SISH_CONTROL_PLANE_MODE=required` へ変更し、`docker compose up -d sish` を実行する
5. manual `.pub` はrequired modeでログインできても全bindが拒否されるため、確認後に手動削除する

認可切替のrollbackは `SISH_CONTROL_PLANE_MODE=audit docker compose up -d sish` です。これは一時的にbind制限を緩和するため、障害復旧後すぐrequiredへ戻してください。DB migration前には `data/control-plane.db*` を整合した状態でbackupしてください。既存の80/443/2222、`keys/`、`ssl/`、`pubkeys/`、Certbot deploy hookは変更していません。

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

