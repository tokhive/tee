package shared

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestStartHTTPServerRejectsOccupiedPortBeforeReadiness(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = occupied.Close() })

	running, err := StartHTTPServer(&http.Server{Addr: occupied.Addr().String()}, false)
	if err == nil {
		if running != nil {
			_ = running.Shutdown(context.Background())
		}
		t.Fatal("occupied port unexpectedly reached the serving state")
	}
	if !strings.Contains(err.Error(), "bind HTTP server") {
		t.Fatalf("bind error = %v, want bind HTTP server context", err)
	}
}

func TestStartHTTPServerSurfacesServeFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	running, err := StartHTTPServerOnListener(&http.Server{}, listener, false)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-running.Errors():
		if err == nil {
			t.Fatal("closed listener produced a nil Serve result")
		}
	case <-time.After(time.Second):
		t.Fatal("Serve failure was not observable")
	}
}

func TestStartHTTPServerNormalShutdownIsNotFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	running, err := StartHTTPServerOnListener(&http.Server{}, listener, false)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := running.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-running.Errors():
		if err != nil {
			t.Fatalf("normal shutdown result = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("normal shutdown did not complete Serve")
	}
}

func TestStartHTTPServerOnListenerRejectsInvalidOwnershipSynchronously(t *testing.T) {
	t.Run("nil server closes transferred listener", func(t *testing.T) {
		listener := &trackingListener{}
		running, err := StartHTTPServerOnListener(nil, listener, false)
		if err == nil || running != nil {
			t.Fatalf("result = (%v, %v), want nil runner and error", running, err)
		}
		if !listener.closed {
			t.Fatal("rejected transferred listener was not closed")
		}
	})

	t.Run("nil listener", func(t *testing.T) {
		running, err := StartHTTPServerOnListener(&http.Server{}, nil, false)
		if err == nil || running != nil {
			t.Fatalf("result = (%v, %v), want nil runner and error", running, err)
		}
	})
}

func TestWaitAndShutdownHTTPServerDoesNotMaskSimultaneousServeFailure(t *testing.T) {
	wantErr := errors.New("injected Serve failure")
	running := &BoundHTTPServer{server: &http.Server{}, errors: make(chan error, 1)}
	running.errors <- wantErr
	close(running.errors)
	stop := make(chan os.Signal, 1)
	stop <- syscall.SIGTERM

	serveErr, shutdownErr := WaitAndShutdownHTTPServer(running, stop, time.Second)
	if shutdownErr != nil {
		t.Fatalf("shutdown error = %v", shutdownErr)
	}
	if !errors.Is(serveErr, wantErr) {
		t.Fatalf("Serve result = %v, want %v", serveErr, wantErr)
	}
}

type trackingListener struct {
	closed bool
}

func (*trackingListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (l *trackingListener) Close() error {
	l.closed = true
	return nil
}
func (*trackingListener) Addr() net.Addr { return trackingAddr("tracking") }

type trackingAddr string

func (a trackingAddr) Network() string { return string(a) }
func (a trackingAddr) String() string  { return string(a) }
