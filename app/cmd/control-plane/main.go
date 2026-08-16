package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"tunnel-control-plane/internal/config"
	"tunnel-control-plane/internal/integration"
	"tunnel-control-plane/internal/service"
	"tunnel-control-plane/internal/store"
	"tunnel-control-plane/internal/web"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := config.Load()
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}
	if err = os.MkdirAll(filepath.Dir(cfg.DatabasePath), 0750); err != nil {
		logger.Error("database directory setup failed", "error", err)
		os.Exit(1)
	}
	st, err := store.Open(cfg.DatabasePath)
	if err != nil {
		logger.Error("database startup failed", "error", err)
		os.Exit(1)
	}
	defer st.Close()
	dns := &integration.VercelDNS{Token: cfg.VercelToken, Domain: cfg.TunnelDomain}
	sish, err := integration.NewSishClient(cfg.SISHManagementURL, cfg.SISHManagementTokenFile)
	if err != nil {
		logger.Error("sish management configuration failed", "error", err)
		os.Exit(1)
	}
	publicKey, err := os.ReadFile(cfg.SystemPublicKeyFile)
	if err != nil {
		logger.Error("system public key read failed", "error", err)
		os.Exit(1)
	}
	canonicalKey, fingerprint, err := service.ValidatePublicKey(string(publicKey))
	if err != nil {
		logger.Error("system public key is invalid", "error", err)
		os.Exit(1)
	}
	if err = st.EnsureSystemResources(context.Background(), "control-plane-tunnel", canonicalKey, fingerprint, cfg.ControlPlaneSubdomain); err != nil {
		logger.Error("system resource registration failed", "error", err)
		os.Exit(1)
	}
	keyWriter := integration.PublicKeyWriter{Dir: cfg.PubKeysDir}
	svc := &service.Service{Store: st, DNS: dns, Keys: keyWriter, Tunnels: sish, Logger: logger, ControlPlaneSubdomain: cfg.ControlPlaneSubdomain}
	if err = svc.Reconcile(context.Background()); err != nil {
		logger.Error("authorized key reconciliation failed", "error", err)
		os.Exit(1)
	}
	if err = st.CleanupAuth(context.Background(), time.Now()); err != nil {
		logger.Error("expired authentication cleanup failed", "error", err)
		os.Exit(1)
	}
	if err = st.CleanupSecurityTelemetry(context.Background(), time.Now()); err != nil {
		logger.Error("expired security telemetry cleanup failed", "error", err)
		os.Exit(1)
	}
	app, err := web.New(cfg, st, svc, logger)
	if err != nil {
		logger.Error("web startup failed", "error", err)
		os.Exit(1)
	}
	httpServer := &http.Server{Addr: cfg.Addr, Handler: app.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
	internalServer := &http.Server{Addr: cfg.InternalAddr, Handler: web.InternalServer{Store: st, TokenFile: cfg.InternalTokenFile, Domain: cfg.TunnelDomain}.Handler(), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16 << 10}
	workerCtx, workerCancel := context.WithCancel(context.Background())
	defer workerCancel()
	go (&service.OutboxWorker{Store: st, Keys: keyWriter, Tunnels: sish, Logger: logger, Interval: time.Second, Domain: cfg.TunnelDomain}).Run(workerCtx)
	go (&service.TunnelSynchronizer{Store: st, Provider: sish, Logger: logger, Interval: 5 * time.Second}).Run(workerCtx)
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-workerCtx.Done():
				return
			case now := <-ticker.C:
				if cleanupErr := st.CleanupSecurityTelemetry(workerCtx, now); cleanupErr != nil {
					logger.Error("expired security telemetry cleanup failed", "error", cleanupErr)
				}
			}
		}
	}()
	go func() {
		logger.Info("control plane listening", "address", cfg.Addr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server failed", "error", err)
			os.Exit(1)
		}
	}()
	go func() {
		logger.Info("internal control API listening", "address", cfg.InternalAddr)
		if err := internalServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("internal server failed", "error", err)
			os.Exit(1)
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	workerCancel()
	if err = errors.Join(httpServer.Shutdown(ctx), internalServer.Shutdown(ctx)); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
	}
}
