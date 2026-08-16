# Tunnel Service

`sish`を利用した、Discord認証・予約制のリバーストンネル基盤です。

- 公開トンネル: `*.${TUNNEL_DOMAIN}`
- SSH endpoint: `${SSH_HOST}:2222`
- 管理画面: `https://${CONTROL_PLANE_SUBDOMAIN}.${TUNNEL_DOMAIN}`
- 通常トンネル: active user・enabled SSH key・所有する予約済みsubdomainを毎bind時に照合
- 管理画面トンネル: 専用system key・system subdomainを起動時に自動登録

`audit` / `required`の意味は変更していません。通常運用は`required`です。

## 公開portとsecurity boundary

| Port       | 用途         |
| ---------- | ------------ |
| `80/tcp`   | HTTP tunnel  |
| `443/tcp`  | HTTPS tunnel |
| `2222/tcp` | sish SSH     |

Control Plane `8080`、内部認可API `8081`、sish management API `8082`はhost networkのloopbackでのみ使用します。Composeは`8080`を`ports` / `expose`しません。

- Control Plane / control-plane-tunnel: 非root
- sish: UID 0、全capability drop後に`NET_BIND_SERVICE`だけ付与
- 全service: read-only root filesystem、`no-new-privileges`
- secretは必要なserviceにだけread-only mount
- 管理トンネル秘密鍵はcontrol-plane-tunnelだけにmount

# 新規KAGOYA Cloud VPSセットアップ

Ubuntu 24.04 LTSを前提とします。

## 1. 前提ソフトウェア

- Git
- Docker Engine / Docker Compose plugin
- OpenSSH client (`ssh-keygen`)
- OpenSSL
- curl / Python 3（Certbot DNS hook）
- Certbot

Dockerは公式手順で導入し、deploy userがDockerを実行できる状態にします。

```bash
docker --version
docker compose version
git --version
ssh -V
openssl version
certbot --version
```

## 2. DNS

Vercel DNSで次を作成します。

```text
ssh.example.com  A  <VPS IPv4>
*.example.com    A  <VPS IPv4>
```

`ssh` labelとwildcardは一般ユーザーの予約対象ではありません。既存の完全一致record（例: `app.example.com`）は予約時の競合として拒否します。wildcard record自体は完全一致競合にしません。Vercel API障害時はfail closedです。

```bash
getent ahostsv4 ssh.example.com
getent ahostsv4 tunnel.example.com
```

## 3. Discord Developer Portal

1. <https://discord.com/developers/applications> でApplicationを作成
2. OAuth2 Redirectsへ管理画面callbackを追加

```text
https://tunnel.example.com/auth/callback
```

`tunnel`を別labelにする場合は、その値へ読み替えます。

3. Client ID / Client Secretを控える
4. Discord Developer Modeで管理者のuser IDを取得

Botは不要です。

## 4. 最小`.env`

```bash
git clone https://github.com/smdhnz/tunnel-service.git
cd tunnel-service
cp .env.example .env
nano .env
```

```dotenv
TUNNEL_DOMAIN=example.com
SSH_HOST=ssh.example.com
CONTROL_PLANE_SUBDOMAIN=tunnel

DISCORD_CLIENT_ID=...
DISCORD_CLIENT_SECRET=...
ADMIN_DISCORD_IDS=123456789012345678
VERCEL_TOKEN=...

SISH_CONTROL_PLANE_MODE=required
CONTROL_PLANE_UID=1000
CONTROL_PLANE_GID=1000
```

`CONTROL_PLANE_UID/GID`はdeploy userへ合わせます。

```bash
id -u
id -g
```

非rootでsetupする場合、一致しなければfail fastします。rootでsetupする場合も、container実行user用の非0 UID/GIDを指定して所有者を設定します。UID/GID `0`は拒否されます。

管理画面host、OAuth callback、reverse tunnel labelはComposeが次のように生成します。`tunnel`はコード固定ではありません。

```text
${CONTROL_PLANE_SUBDOMAIN}.${TUNNEL_DOMAIN}
https://${CONTROL_PLANE_SUBDOMAIN}.${TUNNEL_DOMAIN}/auth/callback
-R ${CONTROL_PLANE_SUBDOMAIN}:80:127.0.0.1:8080
```

## 5. setup

```bash
./scripts/setup.sh
```

setupはDockerを起動しません。次を冪等に実行します。

- 必須env、label、UID/GID、必要commandを生成前に検証
- `data/ pubkeys/ keys/ ssl/ secrets/`をmode `0750`で作成し、root実行時はDB/WALを含む配下全体のUID/GIDを整合
- 内部token / session secretを暗号学的乱数で作成
- Discord / Vercel secretを`.env`からsecret fileへ初回だけcopy
- sish永続host keyをed25519・passphraseなしで作成（private keyはsishの実行groupが読める`0640`）
- 管理トンネル専用keyをed25519・passphraseなしで作成
- 管理公開鍵をsish認証directoryへ配置
- 永続host keyからstrictな`secrets/sish-known-hosts`を生成
- 所有者・mode・key pair整合を検証

全処理は`umask 077`です。既存secret、key、DB、証明書を上書きしません。欠落artifactだけを再生成でき、既存system公開鍵との不一致は安全側で停止します。rootによる所有者整合ではpersistent directory内のsymlink・hard linkを拒否し、repository外を変更しません。secret値は標準出力へ出しません。

`known_hosts`はネットワークから未検証host keyを取得せず、sishが実際に使用する永続秘密鍵から公開鍵を導出します。このためsish起動前に生成でき、`StrictHostKeyChecking=yes`を維持できます。setup出力のfingerprintを運用記録へ保存してください。

生成物:

| File                                   | 理由 / 読み取るservice                                                 |
| -------------------------------------- | ---------------------------------------------------------------------- |
| `secrets/control-plane-internal-token` | sish→Control Plane認可API認証 / sish, Control Plane                    |
| `secrets/sish-management-token`        | snapshot・disconnect API / sish, Control Plane                         |
| `secrets/session-secret`               | Web session HMAC / Control Plane                                       |
| `secrets/discord-client-secret`        | OAuth code exchange / Control Plane                                    |
| `secrets/vercel-token`                 | DNS exact conflict check / Control Plane（Certbot hookは`.env`を使用） |
| `keys/ssh_key`                         | sish host fingerprint永続化 / sish                                     |
| `secrets/control-plane-tunnel-key`     | 管理画面reverse tunnel / control-plane-tunnelのみ                      |
| `secrets/control-plane-tunnel-key.pub` | system key起動時登録 / Control Plane                                   |
| `pubkeys/system-control-plane.pub`     | sish SSH認証 / sish                                                    |
| `secrets/sish-known-hosts`             | MITM防止 / control-plane-tunnel                                        |

Discord / Vercel secretを意図的にrotationする場合、service停止・backup後に対象secret fileを削除してsetupを再実行します。setupは値変更だけでは既存fileを上書きしません。

## 6. wildcard TLS

TLSはLet's Encrypt wildcard証明書とVercel DNS-01 hookを使用します。初回のLet's Encrypt email・利用規約同意は運用者の明示操作が必要なため、setupは証明書を自動取得しません。証明書がない場合もsetup自体は安全に完了し、次操作を表示します。

この節のshell変数を読み込みます（値は表示しません）。

```bash
set -a
source .env
set +a
chmod +x scripts/certbot-auth.sh scripts/certbot-cleanup.sh
sudo certbot certonly \
  --manual \
  --preferred-challenges dns \
  --manual-auth-hook "$PWD/scripts/certbot-auth.sh" \
  --manual-cleanup-hook "$PWD/scripts/certbot-cleanup.sh" \
  --cert-name "$TUNNEL_DOMAIN" \
  -d "*.${TUNNEL_DOMAIN}"
```

Certbotのpromptでemailを入力し、利用規約へ同意します。hookは`_acme-challenge` TXTだけを一時作成・削除します。作成したrecord IDは`secrets/.certbot-vercel-record-id`へmode `0600`でatomic保存し、残存stateやsymlinkがある場合は上書きせず停止します。cleanupはVercel APIのDELETE成功後だけstateを削除するため、失敗時は同じcleanup hookを再実行できます。

初回証明書を配置します（既存先がある場合は先に内容を確認し、上書きしないでください）。

```bash
test ! -e "ssl/${TUNNEL_DOMAIN}.crt"
test ! -e "ssl/${TUNNEL_DOMAIN}.key"
sudo install -o "$CONTROL_PLANE_UID" -g "$CONTROL_PLANE_GID" -m 0644 \
  "/etc/letsencrypt/live/${TUNNEL_DOMAIN}/fullchain.pem" \
  "ssl/${TUNNEL_DOMAIN}.crt"
sudo install -o "$CONTROL_PLANE_UID" -g "$CONTROL_PLANE_GID" -m 0640 \
  "/etc/letsencrypt/live/${TUNNEL_DOMAIN}/privkey.pem" \
  "ssl/${TUNNEL_DOMAIN}.key"
```

renewal deploy hookを冪等にinstallします。更新成功時だけ証明書をcopyし、sishをrestartします。

```bash
./scripts/install-certbot-deploy.sh
sudo certbot renew --dry-run --run-deploy-hooks
```

Certbot管理下の`/etc/letsencrypt`をsetupは変更・削除しません。

## 7. 起動

```bash
docker compose config --quiet
docker compose up --build -d
```

初回Control Plane起動時、migration後に次をDBへsystem resourceとして自動登録します。

- `CONTROL_PLANE_SUBDOMAIN`
- `secrets/control-plane-tunnel-key.pub`のfingerprint

通常`users` / `ssh_keys` / `subdomains` rowを偽装しません。独立した`system_ssh_keys` / `system_subdomains`を使い、認可・connect event・snapshotの共通整合性検証を通します。system keyはsystem subdomainだけbindでき、一般keyはbindできません。

## 8. auditからrequiredへの切替

新規環境は最初から`required`を推奨します。既存manual keyの移行だけ一時的に使います。

```dotenv
SISH_CONTROL_PLANE_MODE=audit
```

- `audit`: callback結果を記録しつつ既存bindを継続。security boundaryとして使わない
- `required`: deny・timeout・error・未予約・所有外をfail closedで拒否

利用者のDiscord login、key登録、subdomain予約、deny候補確認後:

```bash
sed -i 's/^SISH_CONTROL_PLANE_MODE=audit$/SISH_CONTROL_PLANE_MODE=required/' .env
unset SISH_CONTROL_PLANE_MODE
docker compose up -d --force-recreate sish
docker compose restart control-plane-tunnel
```

## 9. 正常性確認

```bash
set -a
source .env
set +a
docker compose ps
curl -fsS http://127.0.0.1:8080/healthz
curl -I "https://${CONTROL_PLANE_SUBDOMAIN}.${TUNNEL_DOMAIN}"
docker compose logs --since=5m | grep -iE 'panic|fatal|permission denied' || true
```

期待値:

- 全service `Up`
- healthz `ok`
- 管理画面HTTP `200`またはloginへのredirect
- 管理画面を手動key登録・subdomain予約せず利用可能

一般ユーザーの動作確認:

1. Discord login
2. OpenSSH公開鍵を登録
3. `demo`を予約
4. 接続

```bash
ssh -N -i ~/.ssh/id_ed25519 -p 2222 \
  -R demo:80:127.0.0.1:3000 "$SSH_HOST"
```

未予約label、他user所有label、`ssh`、`CONTROL_PLANE_SUBDOMAIN`、`_acme-challenge`、既存固定予約語は拒否されます。

# 更新

先に下記「Backup / Restore」のbackup手順を完了してから更新します。

```bash
cd ~/tunnel-service
git pull --ff-only
./scripts/setup.sh
docker compose config --quiet
docker compose up --build -d
```

sish再作成時、接続中のuser tunnelは再接続が必要です。管理トンネルは`restart: unless-stopped`で再接続します。

# Backup / Restore

対象:

```text
.env
data/       # SQLite DB（WAL含む）
pubkeys/    # sish認証公開鍵
keys/       # sish host key
ssl/        # 配置済み証明書
secrets/    # token・管理トンネルkey・known_hosts
/etc/letsencrypt/  # Certbot account・renewal state
```

SQLiteは稼働中にDB本体だけcopyしません。次はrepository artifactとCertbot stateを一度に保存する単独実行可能な手順です。

```bash
cd ~/tunnel-service
BACKUP="$HOME/tunnel-service-backup-$(date +%Y%m%d-%H%M%S)"
install -d -m 0700 "$BACKUP"
docker compose stop control-plane
if cp -a .env data pubkeys keys ssl secrets "$BACKUP/"; then
  docker compose start control-plane
else
  docker compose start control-plane
  exit 1
fi
sudo tar -C /etc -czf "$BACKUP/letsencrypt.tar.gz" letsencrypt
printf 'Backup: %s\n' "$BACKUP"
```

Restore（`BACKUP`を実際のbackup pathへ設定）:

```bash
cd ~/tunnel-service
BACKUP=/path/to/tunnel-service-backup-YYYYmmdd-HHMMSS
docker compose down
cp -a "$BACKUP/.env" "$BACKUP/data" "$BACKUP/pubkeys" \
  "$BACKUP/keys" "$BACKUP/ssl" "$BACKUP/secrets" .
sudo tar -C /etc -xzf "$BACKUP/letsencrypt.tar.gz"
./scripts/setup.sh
docker compose up --build -d
```

restore先のdeploy user UID/GIDが異なる場合は`.env`を修正し、rootでsetupして所有者を整合させます。鍵・証明書を失った状態で既存fileを空fileとして作らないでください。

# Troubleshooting

## setupが必須env不足で停止

```bash
grep -E '^(TUNNEL_DOMAIN|SSH_HOST|CONTROL_PLANE_SUBDOMAIN|DISCORD_CLIENT_ID|VERCEL_TOKEN|CONTROL_PLANE_UID|CONTROL_PLANE_GID)=' .env
```

secret値そのものはterminalへ表示しないでください。

## UID/GID mismatch / permission denied

```bash
id -u; id -g
stat -c '%u:%g %a %n' data pubkeys keys ssl secrets
```

`.env`を実行userへ合わせるか、rootで非0のdeploy UID/GIDを指定して`./scripts/setup.sh`を再実行します。setupは内容を上書きせずownership/modeを検証・修正します。

## system public key mismatch

`secrets/control-plane-tunnel-key.pub`と`pubkeys/system-control-plane.pub`の一方だけを交換しています。稼働を停止し、backupから同じkey pairをrestoreしてください。setupは不一致を自動上書きしません。

## known_hosts mismatch

`SSH_HOST`または`keys/ssh_key`が既存`secrets/sish-known-hosts`と不一致です。意図したhost key rotationなら停止・backup・fingerprint確認後にknown_hostsを削除し、setupで再生成します。`StrictHostKeyChecking=no`は使用しません。

## TLS file missing

```bash
set -a
source .env
set +a
ls -l "ssl/${TUNNEL_DOMAIN}.crt" "ssl/${TUNNEL_DOMAIN}.key"
sudo certbot certificates
```

上記「wildcard TLS」を完了してからsishを起動します。

## 管理画面トンネルがrequiredで拒否

```bash
docker compose logs --tail=100 control-plane sish control-plane-tunnel
ls -l secrets/control-plane-tunnel-key.pub pubkeys/system-control-plane.pub
```

Control Plane起動時にsystem resource登録が失敗していないか確認します。GUIから管理keyや管理subdomainを登録する手順はありません。

## mode変更が反映されない

現在shellに`source .env`した古い値が残っています。

```bash
unset SISH_CONTROL_PLANE_MODE
docker compose up -d --force-recreate sish
```

## Vercel API障害

予約はfail closedになります。token権限、domain、Vercel statusを確認し、障害中に認可を迂回しないでください。

# 開発・検証

```bash
./scripts/setup_test.sh
./scripts/compose_test.sh
cd app && go test ./...
docker compose config --quiet
docker compose build
```

setup testは一時fixtureだけを使用し、実VPSのDocker・secret・証明書を変更しません。Compose testはconfig展開だけを行い、containerを起動しません。
