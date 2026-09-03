package hub

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/internal/canonical"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// sessionTunnel is a full-duplex pipe: the Hub runs its Read and Write on two
// goroutines at once. A naive implementation serializes both behind one lock,
// so a downlink frame arriving while the uplink goroutine holds the lock can
// wedge the whole session. This drives a real WebSocket end-to-end, with the
// provider streaming down and the user streaming up concurrently, so a deadlock
// or a data race in the lock split surfaces immediately.

func TestSessionTunnelFullDuplexNoDeadlock(t *testing.T) {
	const downFrames = 200

	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		// Echo protocol: for each uplink frame, echo one downlink frame back.
		// The Hub's reader therefore blocks waiting for a frame the Hub's own
		// writer must first send — the exact shape that deadlocks if Read and
		// Write share a single lock.
		for i := 0; i < downFrames; i++ {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
			if err := conn.WriteMessage(websocket.BinaryMessage, []byte("down")); err != nil {
				return
			}
		}
		signed := proof.SignedReceipt{Receipt: proof.Receipt{Version: proof.VersionV1}}
		raw, err := canonical.Marshal(signed)
		if err != nil {
			return
		}
		receiptJSON, _ := json.Marshal(map[string]string{
			"receipt": base64.StdEncoding.EncodeToString(raw),
		})
		_ = conn.WriteMessage(websocket.TextMessage, receiptJSON)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	tun := &sessionTunnel{conn: conn}

	// Upstream writer pushes frames while the downstream reader consumes them.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < downFrames; i++ {
			if _, err := tun.Write([]byte("up")); err != nil {
				// The provider closing mid-session makes later uplink writes
				// fail; in production that is the normal unwind, not a bug.
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		got := 0
		for {
			n, err := tun.Read(buf)
			got += n
			if err != nil {
				if err.Error() != "EOF" {
					t.Errorf("read: %v", err)
				}
				break
			}
		}
		if got == 0 {
			t.Errorf("read no downlink bytes")
		}
	}()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("session tunnel deadlocked under concurrent full-duplex traffic")
	}

	if _, err := tun.Receipt(); err != nil {
		t.Fatalf("receipt should be available after the session ended: %v", err)
	}
}
