// Command agent is the TokenHive Provider Agent: a process a quota contributor
// runs on their own machine so a TEE can egress through their network. It is a
// thin wrapper over provider.NewAgent.
package main

import (
	"flag"
	"log"
	"strings"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/provider"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18092", "listen address")
	targets := flag.String("targets", "127.0.0.1:18080", "comma-separated host:port the agent may dial (the AI provider endpoint)")
	flag.Parse()

	allowed := make([]string, 0, 4)
	for _, t := range strings.Split(*targets, ",") {
		if t = strings.TrimSpace(t); t != "" {
			allowed = append(allowed, t)
		}
	}

	agent, err := provider.NewAgent(provider.AgentConfig{
		AllowedTargets: allowed,
	})
	if err != nil {
		log.Fatalf("create agent: %v", err)
	}
	log.Printf("provider agent listening on %s (allowlist: %v)", *addr, allowed)
	log.Fatal(agent.ListenAndServe(*addr))
}
