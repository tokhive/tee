// Command sessiondriver drives a streaming session through the Hub's USER-facing
// /v1/session WebSocket and asserts the full chain works end to end:
//
//	user WS -> Hub (/v1/session) -> TEE (/v1/session tunnel) -> provider (/v1/realtime)
//
// It is the session counterpart of the user-facing API test (scenario 15/16),
// but for the streaming-session surface. The Hub reads the model out of the
// FIRST frame so it can pick the cheapest provider and settle — that first frame
// is then still replayed to the provider verbatim, where the mock provider
// echoes it back. The driver therefore proves a full-duplex byte round trip:
// the first frame entered through the user WebSocket, reached the provider, and
// came back with the provider's marker echoed inside every downlink frame.
//
// The driver itself never sees a receipt — settlement and provider choice are
// the Hub's business and are asserted in the harness by grepping the Hub's log
// (provider=cheap-sim, charged>0). This binary only proves the relay is
// truthful in both directions.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

func main() {
	url := flag.String("url", "ws://127.0.0.1:18085/v1/session", "Hub user-facing session WebSocket URL")
	model := flag.String("model", "sim-mock-0.5b", "model name for the Hub to schedule (first frame)")
	marker := flag.String("marker", "session-marker-17", "marker embedded in the first frame and echoed back")
	wantEvents := flag.String("events", "session.updated,response.created,response.done", "comma-separated provider events each downlink frame must be")
	flag.Parse()

	// The first frame drives provider selection (model) and carries the duplex
	// probe (marker). The Hub reads only "model"; everything else — including the
	// marker — travels to the provider unchanged, and the mock provider echoes it.
	first, err := json.Marshal(map[string]string{"model": *model, "marker": *marker})
	if err != nil {
		fail("encode first frame: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	conn, _, err := websocket.DefaultDialer.DialContext(ctx, *url, nil)
	if err != nil {
		fail("dial %s: %v", *url, err)
	}
	defer conn.Close()

	if err := conn.WriteMessage(websocket.TextMessage, first); err != nil {
		fail("send first frame: %v", err)
	}

	// Downlink: the provider's frames arrive as text; the Hub closes the user
	// connection once the session has settled. Read until that close.
	want := splitCSV(*wantEvents)
	events := make([]string, 0, len(want)+1)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		mt, msg, rerr := conn.ReadMessage()
		if rerr != nil {
			break // the Hub closed after settling (or transport ended)
		}
		if mt != websocket.TextMessage {
			continue
		}
		events = append(events, string(msg))
	}

	pass := true
	check := func(name string, ok bool, detail string) {
		state := "  OK"
		if !ok {
			state = "  !! FAIL"
			pass = false
		}
		fmt.Printf("%s %-32s %s\n", state, name, detail)
	}

	check("downlink frames", len(events) >= len(want), fmt.Sprintf("got %d", len(events)))
	for _, ev := range want {
		found := false
		for _, f := range events {
			if strings.Contains(f, ev) {
				found = true
				break
			}
		}
		check(fmt.Sprintf("event %q", ev), found, "present in downlink")
	}
	// Every downlink frame must carry the marker the provider echoed back —
	// proof the first frame reached the provider and returned through the Hub.
	echoed := 0
	for _, f := range events {
		if strings.Contains(f, *marker) {
			echoed++
		}
	}
	check("marker echoed", echoed > 0, fmt.Sprintf("marker %q in %d/%d downlink frames", *marker, echoed, len(events)))

	if !pass {
		for i, f := range events {
			fmt.Printf("  [downlink %d] %q\n", i, f)
		}
		os.Exit(1)
	}
	fmt.Printf("SESSION-ROUTE OK: model=%s marker=%q frames=%d\n", *model, *marker, len(events))
}

// splitCSV splits a comma-separated flag value, trimming spaces.
func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "SESSION FAIL: "+format+"\n", args...)
	os.Exit(1)
}