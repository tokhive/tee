package shared

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

// BoundHTTPServer owns a listener that was successfully bound before the
// caller publishes service readiness. Errors returns the sole Serve result so
// boot code can select it alongside its shutdown signal.
type BoundHTTPServer struct {
	server *http.Server
	errors chan error
}

// StartHTTPServer binds synchronously, then starts serving. A successful return
// is the readiness boundary: the configured address is already reserved.
func StartHTTPServer(server *http.Server, serveTLS bool) (*BoundHTTPServer, error) {
	if server == nil {
		return nil, fmt.Errorf("HTTP server is nil")
	}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return nil, fmt.Errorf("bind HTTP server %s: %w", server.Addr, err)
	}
	return StartHTTPServerOnListener(server, listener, serveTLS)
}

// StartHTTPServerOnListener serves on an already-bound listener. It supports
// inherited sockets and deterministic Serve-failure tests. Ownership transfers
// on entry; rejected inputs close any non-nil listener synchronously.
func StartHTTPServerOnListener(server *http.Server, listener net.Listener, serveTLS bool) (*BoundHTTPServer, error) {
	if server == nil {
		if listener != nil {
			_ = listener.Close()
		}
		return nil, fmt.Errorf("HTTP server is nil")
	}
	if listener == nil {
		return nil, fmt.Errorf("HTTP listener is nil")
	}
	run := &BoundHTTPServer{server: server, errors: make(chan error, 1)}
	go func() {
		var err error
		if serveTLS {
			err = server.ServeTLS(listener, "", "")
		} else {
			err = server.Serve(listener)
		}
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		run.errors <- err
		close(run.errors)
	}()
	return run, nil
}

func (s *BoundHTTPServer) Errors() <-chan error {
	if s == nil {
		closed := make(chan error)
		close(closed)
		return closed
	}
	return s.errors
}

func (s *BoundHTTPServer) Shutdown(ctx context.Context) error {
	if s == nil || s.server == nil {
		return nil
	}
	return s.server.Shutdown(ctx)
}

// WaitAndShutdownHTTPServer waits for either process shutdown or Serve exit,
// then shuts the server down and reconciles the single Serve result. If both
// become ready together, a signal-selected branch still drains the Serve result
// so an operational failure cannot be mistaken for a normal shutdown.
func WaitAndShutdownHTTPServer(server *BoundHTTPServer, stop <-chan os.Signal, timeout time.Duration) (serveErr, shutdownErr error) {
	if server == nil {
		return nil, fmt.Errorf("bound HTTP server is nil")
	}
	serveResultObserved := false
	select {
	case <-stop:
	case err, ok := <-server.Errors():
		serveResultObserved = true
		if ok {
			serveErr = err
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	shutdownErr = server.Shutdown(shutdownCtx)
	if !serveResultObserved {
		if err, ok := <-server.Errors(); ok {
			serveErr = err
		}
	}
	return serveErr, shutdownErr
}
