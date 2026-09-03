// Command agent is the TokenHive Provider Agent: a process a quota contributor
// runs on their own machine so a TEE can egress through their network. It is a
// thin wrapper over provider.NewAgent.
//
// The agent lives behind a home NAT, so it cannot be dialed: it dials the Hub's
// AgentGate and keeps the reverse tunnel open, reconnecting whenever it drops.
// While online, the Hub routes this provider's egress through it; the TEE's TLS
// session with the AI provider travels over that tunnel end to end, so the agent
// only ever sees encrypted bytes.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/hub"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/provider"
)

func main() {
	gate := flag.String("hub", "ws://127.0.0.1:18085/v1/agent", "Hub AgentGate WebSocket URL the agent dials to come online")
	key := flag.String("key", "", "shared key to present at dial-in (must match the Hub's AgentSecret)")
	providerName := flag.String("provider", "", "provider this agent egresses for")
	name := flag.String("name", "", "optional human display label for this agent")
	price := flag.Int64("price", 0, "per-request price in micro-units; 0 accepts the Hub's platform default for this provider")
	targets := flag.String("targets", "127.0.0.1:18080", "comma-separated host:port the agent may dial (the AI provider endpoint)")
	tap := flag.String("tap", "", "file to mirror every relayed byte into (test/demo: proves the agent only sees ciphertext)")
	timeout := flag.Duration("connect-timeout", 10*time.Second, "bounds dialing the Hub and each upstream")
	reconnect := flag.Duration("reconnect", time.Second, "pause between reconnect attempts after the tunnel drops")
	flag.Parse()

	if *key == "" {
		log.Fatal("agent requires -key")
	}
	if *providerName == "" {
		log.Fatal("agent requires -provider")
	}
	allowed := make([]string, 0, 4)
	for _, t := range strings.Split(*targets, ",") {
		if t = strings.TrimSpace(t); t != "" {
			allowed = append(allowed, t)
		}
	}

	cfg := provider.AgentConfig{
		HubGateURL:     *gate,
		SharedKey:      []byte(*key),
		AllowedTargets: allowed,
		ConnectTimeout: *timeout,
		ReconnectDelay: *reconnect,
		Self: hub.AgentRegister{
			Provider:    *providerName,
			DisplayName: *name,
		},
	}
	if *price > 0 {
		cfg.Self.SelfPrice = &hub.RateCard{PerRequestMicros: uint64(*price)}
	}
	if *tap != "" {
		f, err := os.Create(*tap)
		if err != nil {
			log.Fatalf("open tap file: %v", err)
		}
		cfg.Tap = f
	}

	agent, err := provider.NewAgent(cfg)
	if err != nil {
		log.Fatalf("create agent: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("provider agent %s online via %s (allowlist: %v, price: %s)",
		*providerName, *gate, allowed, priceLabel(*price))
	if err := agent.Run(ctx); err != nil {
		log.Fatalf("agent: %v", err)
	}
}

func priceLabel(micros int64) string {
	if micros <= 0 {
		return "platform default"
	}
	return strconv.FormatFloat(float64(micros)/1e6, 'f', -1, 64) + " units/request"
}
