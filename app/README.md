# Control Plane

WSLでのローカル起動（リポジトリルートの `.env` を読み込んでから実行）:

```bash
cd app
set -a; source ../.env; set +a
go run ./cmd/control-plane
```

SQLite migrationは起動時に `internal/store/migrations/` から適用されます。開発時もVercel tokenが未設定ならサブドメイン予約はfail closedで拒否され、DNS更新APIは実装していません。
