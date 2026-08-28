# Tunnel Service

`sish`を利用した、Discord認証・予約制のリバーストンネル基盤です。

- 公開トンネル: `*.${TUNNEL_DOMAIN}`
- SSH endpoint: `${SSH_HOST}:2222`
- 管理画面: `https://${CONTROL_PLANE_SUBDOMAIN}.${TUNNEL_DOMAIN}`
- 通常トンネル: active user・enabled SSH key・所有する予約済みsubdomain / TCPポート予約を毎bind時に照合（未予約TCPポートは拒否）
- 管理画面トンネル: 専用system key・system subdomainを起動時に自動登録

`audit` / `required`の意味は変更していません。通常運用は`required`です。

## 公開portとsecurity boundary

| Port              | 用途         |
| ----------------- | ------------ |
| `80/tcp`          | HTTP tunnel  |
| `443/tcp`         | HTTPS tunnel |
| `2222/tcp`        | sish SSH     |
| `10000-65535/tcp` | TCP tunnel   |

VPSのファイアウォールとクラウド側のセキュリティ設定では、TCPトンネル専用範囲`10000-65535/tcp`を一度だけ許可する必要があります。以後は管理画面で予約するポートごとの開放は不要です。このリポジトリはVPSやクラウドの設定を自動変更しません。

UbuntuでUFWを利用する場合は、管理SSHを遮断しないようSSHポートを先に許可してから設定します。管理SSHが22番以外なら`22`を実際のポートへ置き換えます。

```bash
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 2222/tcp
sudo ufw allow 10000:65535/tcp
sudo ufw enable
sudo ufw status numbered
```

KAGOYA Cloud VPSでセキュリティグループを適用すると、登録した許可以外は拒否されます。コントロールパネルでTCP `10000-65535`を範囲指定できない場合は、そのセキュリティグループを外し、上記UFWで制御します。セキュリティグループを外す前にUFWの管理SSH・HTTP・HTTPS・sish SSH・TCP専用範囲が許可済みであることを確認してください。

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

## 2. `.env`を作成

```bash
git clone https://github.com/smdhnz/tunnel-service.git
cd tunnel-service
cp .env.example .env
nano .env
```

最低限、次の値を設定します。

| 変数 | 設定内容 | 設定例 |
| ---- | -------- | ------ |
| `TUNNEL_DOMAIN` | 公開トンネルの基底ドメイン | `example.com` |
| `SSH_HOST` | sishへ接続するSSHホスト | `ssh.example.com` |
| `CONTROL_PLANE_SUBDOMAIN` | 管理画面のサブドメインlabel | `tunnel` |
| `DISCORD_CLIENT_ID` | Discord ApplicationのClient ID | Discord Developer Portalで取得 |
| `DISCORD_CLIENT_SECRET` | Discord ApplicationのClient Secret | Discord Developer Portalで取得 |
| `ADMIN_DISCORD_IDS` | 管理者のDiscord user ID。複数指定はカンマ区切り | `123456789012345678` |
| `VERCEL_TOKEN` | DNS recordを参照・操作できるVercel token | Vercelで発行 |
| `SISH_CONTROL_PLANE_MODE` | 通常は`required` | `required` |
| `CONTROL_PLANE_UID` | deploy userのUID | `id -u`の出力 |
| `CONTROL_PLANE_GID` | deploy userのGID | `id -g`の出力 |

```bash
id -u
id -g
```

`CONTROL_PLANE_UID/GID`は上記コマンドで確認したdeploy userへ合わせます。非rootでsetupする場合、一致しなければfail fastします。rootでsetupする場合も、container実行user用の非0 UID/GIDを指定して所有者を設定します。UID/GID `0`は拒否されます。

以降の`${TUNNEL_DOMAIN}`、`${SSH_HOST}`、`${CONTROL_PLANE_SUBDOMAIN}`は、`.env`に設定した値を表します。shellで使う前に次のように読み込みます。

```bash
set -a
source .env
set +a
```

Composeは設定値から次を生成します。管理画面のlabelやhostはコード固定ではありません。

```text
管理画面:       https://${CONTROL_PLANE_SUBDOMAIN}.${TUNNEL_DOMAIN}
OAuth callback: https://${CONTROL_PLANE_SUBDOMAIN}.${TUNNEL_DOMAIN}/auth/callback
管理トンネル:   -R ${CONTROL_PLANE_SUBDOMAIN}:80:127.0.0.1:8080
```

## 3. DNS

Vercel DNSで次のA recordを作成します。

| Name | Type | Value |
| ---- | ---- | ----- |
| `${SSH_HOST}` | `A` | VPSのIPv4 address |
| `*.${TUNNEL_DOMAIN}` | `A` | VPSのIPv4 address |

`SSH_HOST`のlabelとwildcardは一般ユーザーの予約対象ではありません。既存の完全一致record（例: `app.${TUNNEL_DOMAIN}`）は予約時の競合として拒否します。wildcard record自体は完全一致競合にしません。Vercel API障害時はfail closedです。

DNS反映を確認します。

```bash
getent ahostsv4 "$SSH_HOST"
getent ahostsv4 "${CONTROL_PLANE_SUBDOMAIN}.${TUNNEL_DOMAIN}"
```

## 4. Discord Developer Portal

1. <https://discord.com/developers/applications> でApplicationを作成
2. OAuth2 Redirectsへ次のcallback URLを追加

```text
https://${CONTROL_PLANE_SUBDOMAIN}.${TUNNEL_DOMAIN}/auth/callback
```

3. Client ID / Client Secretを`.env`の`DISCORD_CLIENT_ID` / `DISCORD_CLIENT_SECRET`へ設定
4. Discord Developer Modeで管理者のuser IDを取得し、`.env`の`ADMIN_DISCORD_IDS`へ設定

Botは不要です。

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

TCPトンネルは管理画面で専用範囲（10000〜65535）の対象ポートを先に予約します。Minecraft Java Edition（既定25565）の例:

```bash
ssh -N -i ~/.ssh/id_ed25519 -p 2222 \
  -R 25565:127.0.0.1:25565 "$SSH_HOST"
```

未予約または他ユーザー所有のTCPポートは拒否されます。VPS / クラウド側では上記の専用範囲を一度だけ許可すれば、以後ポートごとの開放は不要です。

公開接続の濫用防止状態は、SSH、HTTP、TCPの各listenerで分離されます。TCPはさらに公開ポート単位で分離されるため、同じNAT配下からの管理画面アクセスやSSHトンネル常時接続がMinecraftなどのTCP接続枠を消費しません。既定の公開TCP制限は送信元IP・公開ポートごとに同時200接続、burst 240接続、毎秒20接続回復です。`compose.yml`では次の引数で明示しています。

```text
--abuse-tcp-max-connections=200
--abuse-tcp-accept-burst=240
--abuse-tcp-accept-rate=20
```

制限違反は成功した接続を挟むとリセットされ、連続5回の違反で一時ブロックに入ります。管理画面の`temporarily_blocked`はブロック中の拒否総数ではなく、新しく一時ブロックへ遷移した回数です。更新前に蓄積済みの値は履歴として残るため、デプロイ直後の表示には旧方式の件数が含まれる場合があります。

sish既定の転送アイドルタイムアウト5秒はMinecraftのkeepalive間隔に対して短いため、`compose.yml`では`--idle-connection-timeout=2m`を指定します。このdeadlineは読み書きのたびに更新され、2分間まったく通信しない接続だけを終了します。

Dockerのログは全serviceで1ファイル1MB、最大2ファイルにローテーションされます。sishは通常のHTTPアクセスと正常なcloseを出力せず、5xxと`--debug`有効時のアクセスだけを記録します。運用確認では`docker compose logs --tail=100 sish`または`docker compose logs --since=5m sish`を使用します。

# 更新

先に下記「Backup / Restore」のbackup手順を完了してから更新します。

```bash
cd ~/tunnel-service
git pull --ff-only
./scripts/setup.sh
docker compose config --quiet
docker compose up --build -d
docker compose ps
```

TCPトンネルを初めて有効化する更新では、上記「公開portとsecurity boundary」のUFWおよびKAGOYAセキュリティグループ設定も実施します。SQLite migrationはControl Plane起動時に自動適用されます。

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
