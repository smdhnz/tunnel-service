package service

import (
	"context"
	"log/slog"
	"time"

	"tunnel-control-plane/internal/model"
	"tunnel-control-plane/internal/store"
)

type TunnelSnapshotProvider interface {
	Active(context.Context) (model.TunnelSnapshot, error)
}
type TunnelSynchronizer struct {
	Store    *store.Store
	Provider TunnelSnapshotProvider
	Logger   *slog.Logger
	Interval time.Duration
}

func (s *TunnelSynchronizer) Run(ctx context.Context) {
	d := s.Interval
	if d <= 0 {
		d = 5 * time.Second
	}
	ticker := time.NewTicker(d)
	defer ticker.Stop()
	s.once(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.once(ctx)
		}
	}
}
func (s *TunnelSynchronizer) once(ctx context.Context) {
	snapshot, err := s.Provider.Active(ctx)
	now := time.Now()
	if err == nil {
		err = s.Store.ReconcileActiveSnapshot(ctx, snapshot, now)
	}
	if err != nil {
		_ = s.Store.MarkTunnelSyncUnavailable(ctx, now)
		if s.Logger != nil {
			s.Logger.Warn("active tunnel synchronization failed", "error", err)
		}
	}
}
func (s *TunnelSynchronizer) SyncOnce(ctx context.Context) error {
	snapshot, err := s.Provider.Active(ctx)
	if err != nil {
		_ = s.Store.MarkTunnelSyncUnavailable(ctx, time.Now())
		return err
	}
	return s.Store.ReconcileActiveSnapshot(ctx, snapshot, time.Now())
}
