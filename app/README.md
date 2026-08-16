# Control Plane

WSLでのローカル起動（リポジトリルートの `.env` を読み込んでから実行）:

```bash
cd app
set -a; source ../.env; set +a
go run ./cmd/control-plane
```

SQLite migrationは起動時に `internal/store/migrations/` から適用されます。開発時もVercel tokenが未設定ならサブドメイン予約はfail closedで拒否され、DNS更新APIは実装していません。

## 管理画面フロントエンド

Vite + React + TypeScript + Tailwind CSSで実装し、本番buildは成果物をGoバイナリへembedします。Node.jsはbuild・開発時のみ必要です。

```bash
# 型検査・テスト・production asset生成
cd frontend
npm ci
npm run typecheck
npm test
npm run build

# 開発（別terminalで上記Go serverを127.0.0.1:8080へ起動）
npm run dev
```

`npm run build`後に`go build ./cmd/control-plane`を実行してください。Docker buildはこの順序をmulti-stage build内で自動実行し、本番runtimeは従来どおりGo単一バイナリです。
