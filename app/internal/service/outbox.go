package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"tunnel-control-plane/internal/model"
	"tunnel-control-plane/internal/store"
)

type TunnelController interface {
	DisconnectKey(context.Context, int64, int64) error
	DisconnectUser(context.Context, int64, int64) error
	DisconnectHost(context.Context, string, int64) error
}

type OutboxWorker struct {
	Store    *store.Store
	Keys     PublicKeyStore
	Tunnels  TunnelController
	Logger   *slog.Logger
	Interval time.Duration
	Domain   string
}

func (w *OutboxWorker) Run(ctx context.Context) {
	interval := w.Interval
	if interval <= 0 {
		interval = time.Second
	}
	w.drain(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.drain(ctx)
		}
	}
}
func (w *OutboxWorker) drain(ctx context.Context) {
	for n := 0; n < 10; n++ {
		items, err := w.Store.PendingOutbox(ctx, 32)
		if err != nil {
			w.log(err)
			return
		}
		if len(items) == 0 {
			return
		}
		for _, item := range items {
			err = w.process(ctx, item)
			if err == nil {
				err = w.Store.CompleteOutbox(ctx, item.ID)
			}
			if err != nil {
				_ = w.Store.RetryOutbox(ctx, item.ID, item.Attempts+1, err.Error())
				w.log(err)
			}
		}
	}
}
func (w *OutboxWorker) process(ctx context.Context, item model.OutboxItem) error {
	var p struct {
		KeyID      int64  `json:"key_id"`
		UserID     int64  `json:"user_id"`
		Generation int64  `json:"generation"`
		Hostname   string `json:"hostname"`
	}
	if err := json.Unmarshal([]byte(item.Payload), &p); err != nil {
		return err
	}
	switch item.Kind {
	case "pubkey.write":
		k, err := w.Store.Key(ctx, p.KeyID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		return w.Keys.Write(k)
	case "pubkey.remove":
		if p.UserID == 0 {
			k, err := w.Store.Key(ctx, p.KeyID)
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
			p.UserID = k.UserID
		}
		return w.Keys.Remove(p.UserID, p.KeyID)
	case "pubkey.reconcile":
		keys, err := w.Store.AuthorizedKeys(ctx)
		if err != nil {
			return err
		}
		return w.Keys.Reconcile(keys)
	case "tunnel.disconnect_key":
		return w.Tunnels.DisconnectKey(ctx, p.KeyID, p.Generation)
	case "tunnel.disconnect_user":
		return w.Tunnels.DisconnectUser(ctx, p.UserID, p.Generation)
	case "tunnel.disconnect_host":
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p.Hostname), "."))
		domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(w.Domain), "."))
		if domain != "" && !strings.HasSuffix(host, "."+domain) {
			host += "." + domain
		}
		return w.Tunnels.DisconnectHost(ctx, host, p.Generation)
	default:
		return errors.New("unknown outbox event")
	}
}
func (w *OutboxWorker) log(err error) {
	if w.Logger != nil {
		w.Logger.Warn("outbox delivery failed", "error", err)
	}
}
func (w *OutboxWorker) ProcessOnce(ctx context.Context) error {
	items, err := w.Store.PendingOutbox(ctx, 1)
	if err != nil || len(items) == 0 {
		return err
	}
	item := items[0]
	if err = w.process(ctx, item); err != nil {
		_ = w.Store.RetryOutbox(ctx, item.ID, item.Attempts+1, err.Error())
		return err
	}
	return w.Store.CompleteOutbox(ctx, item.ID)
}
