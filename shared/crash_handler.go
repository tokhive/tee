package shared

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"sync/atomic"
	"syscall"
	"time"

	"go.uber.org/zap"
)

// Deferred at goroutine root; logs panic + stack to stderr and zap, then re-panics.
func RecoverAndCrash(logger *Logger, where string) {
	r := recover()
	if r == nil {
		return
	}
	stack := debug.Stack()

	fmt.Fprintf(os.Stderr, "\n=== PANIC in %s ===\nvalue: %v\n%s\n", where, r, stack)

	if logger != nil {
		logger.Error("goroutine panic",
			zap.String("where", where),
			zap.Any("recovered", r),
			zap.ByteString("stack", stack),
		)
		_ = logger.Logger.Sync()
	}

	panic(r)
}

// On SIGTERM/SIGINT/SIGQUIT: dump all goroutines, sync log, exit(128+sig).
func InstallSignalCrashHandler(logger *Logger) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	go func() {
		sig := <-sigCh

		buf := make([]byte, 4<<20)
		n := runtime.Stack(buf, true)

		fmt.Fprintf(os.Stderr, "\n=== SIGNAL %s — dumping %d bytes of goroutine state ===\n%s\n",
			sig, n, buf[:n])

		logger.Error("signal received — dumping goroutines before exit",
			zap.String("signal", sig.String()),
			zap.Int("num_goroutines", runtime.NumGoroutine()),
			zap.ByteString("goroutines", buf[:n]),
		)
		_ = logger.Logger.Sync()

		time.Sleep(2 * time.Second) // give log scraper time to drain
		os.Exit(128 + int(sig.(syscall.Signal)))
	}()
}

// Heartbeat the deadlock watchdog reads.
var liveness atomic.Int64

// Logs goroutines + heap every 60s. Updates `liveness` for the watchdog.
func RunRuntimeStatsLogger(ctx context.Context, logger *Logger) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	var ms runtime.MemStats
	liveness.Store(time.Now().UnixNano())
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runtime.ReadMemStats(&ms)
			logger.Info("runtime stats",
				zap.Int("goroutines", runtime.NumGoroutine()),
				zap.Uint64("heap_alloc_mb", ms.HeapAlloc/1024/1024),
				zap.Uint64("heap_sys_mb", ms.HeapSys/1024/1024),
				zap.Uint64("sys_mb", ms.Sys/1024/1024),
				zap.Uint32("num_gc", ms.NumGC),
				zap.Uint64("next_gc_mb", ms.NextGC/1024/1024),
			)
			liveness.Store(time.Now().UnixNano())
		}
	}
}

// Exits the process if RunRuntimeStatsLogger hasn't ticked in 120s.
func RunDeadlockWatchdog(ctx context.Context, logger *Logger) {
	const deadlockThreshold = 120 * time.Second
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			lastNanos := liveness.Load()
			if lastNanos == 0 {
				continue
			}
			gap := now.Sub(time.Unix(0, lastNanos))
			if gap < deadlockThreshold {
				continue
			}

			buf := make([]byte, 4<<20)
			n := runtime.Stack(buf, true)

			fmt.Fprintf(os.Stderr,
				"\n=== DEADLOCK WATCHDOG TRIPPED ===\n"+
					"last runtime-stats heartbeat: %v ago (threshold %v)\n"+
					"goroutines: %d\n"+
					"=== STACK DUMP (%d bytes) ===\n%s\n"+
					"=== END DUMP ===\n",
				gap, deadlockThreshold, runtime.NumGoroutine(), n, buf[:n])
			_ = os.Stderr.Sync()

			if logger != nil {
				go func() {
					logger.Error("deadlock watchdog tripped",
						zap.Duration("gap", gap),
						zap.Int("num_goroutines", runtime.NumGoroutine()),
						zap.ByteString("stacks", buf[:n]),
					)
					_ = logger.Logger.Sync()
				}()
			}

			time.Sleep(1 * time.Second)
			os.Exit(137)
		}
	}
}
