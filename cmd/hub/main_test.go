package main

import "testing"

func TestRequireServeKeys(t *testing.T) {
	cases := []struct {
		name      string
		serveAddr string
		agentKeys string
		relayKey  string
		wantErr   bool
	}{
		{name: "cli one-shot mode needs no keys"},
		{name: "serve mode requires agent keys", serveAddr: ":18085", relayKey: "r", wantErr: true},
		{name: "serve mode requires relay key", serveAddr: ":18085", agentKeys: "p=k", wantErr: true},
		{name: "serve mode with both keys", serveAddr: ":18085", agentKeys: "p=k", relayKey: "r"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := requireServeKeys(tc.serveAddr, tc.agentKeys, tc.relayKey)
			if (err != nil) != tc.wantErr {
				t.Fatalf("requireServeKeys(%q, %q, %q) err = %v, wantErr %t",
					tc.serveAddr, tc.agentKeys, tc.relayKey, err, tc.wantErr)
			}
		})
	}
}
