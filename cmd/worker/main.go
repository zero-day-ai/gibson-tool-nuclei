// nuclei-worker runs the nuclei tool as a Redis queue worker.
package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"os"
	"time"

	healthhttp "github.com/zero-day-ai/sdk/health/http"
	"github.com/zero-day-ai/sdk/tool/worker"
	"github.com/zero-day-ai/sdk/types"
	"github.com/zero-day-ai/gibson-tool-nuclei"
)

func main() {
	redisURL := flag.String("redis-url", os.Getenv("REDIS_URL"), "Redis URL")
	concurrency := flag.Int("concurrency", 0, "Number of concurrent workers")
	shutdownTimeout := flag.Duration("shutdown-timeout", 0, "Graceful shutdown timeout")
	logLevel := flag.String("log-level", os.Getenv("LOG_LEVEL"), "Log level")
	healthPort := flag.Int("health-port", 8080, "Health check HTTP port (default: 8080)")
	flag.Parse()

	level := slog.LevelInfo
	switch *logLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	tool := nuclei.NewTool()

	// Start HTTP health server for Kubernetes probes
	healthCfg := healthhttp.DefaultConfig()
	healthCfg.Port = *healthPort
	healthServer := healthhttp.NewServer(healthCfg)

	// Register liveness check (tool binary exists)
	healthServer.RegisterLivenessCheck("tool", func(ctx context.Context) types.HealthStatus {
		return tool.Health(ctx)
	})

	// Register readiness check (same as liveness for tools)
	healthServer.RegisterReadinessCheck("tool", func(ctx context.Context) types.HealthStatus {
		return tool.Health(ctx)
	})

	if err := healthServer.Start(); err != nil {
		log.Fatalf("Failed to start health server: %v", err)
	}
	logger.Info("health server started", "port", *healthPort)

	// Ensure health server stops on exit
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		healthServer.Stop(ctx)
	}()

	opts := worker.Options{
		RedisURL:        *redisURL,
		Concurrency:     *concurrency,
		ShutdownTimeout: *shutdownTimeout,
		Logger:          logger,
	}

	logger.Info("starting nuclei worker",
		"redis_url", opts.RedisURL,
		"concurrency", opts.Concurrency,
	)

	if err := worker.Run(tool, opts); err != nil {
		log.Fatalf("Worker failed: %v", err)
	}
}
