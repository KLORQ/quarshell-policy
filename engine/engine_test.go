package engine_test

import (
	"context"
	"testing"

	"github.com/KLORQ/quarshell-policy/corepolicy"
	"github.com/KLORQ/quarshell-policy/engine"
)

func TestPinnedPortListOverridesScalarPortAtRuntime(t *testing.T) {
	const source = `version: 1
network_policies:
  pinned-ports:
    endpoints:
      - host: api.example.com
        port: 8443
        ports: [9443, 10443]
`
	doc, err := policy.Parse([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	var allowlist engine.Allowlist
	if err := allowlist.Apply(doc); err != nil {
		t.Fatal(err)
	}
	for _, port := range []int{9443, 10443} {
		decision, err := allowlist.Decide(context.Background(), engine.EgressRequest{Host: "api.example.com", Port: port})
		if err != nil || !decision.Allow {
			t.Errorf("ports list value %d must be allowed: decision=%+v err=%v", port, decision, err)
		}
	}
	decision, err := allowlist.Decide(context.Background(), engine.EgressRequest{Host: "api.example.com", Port: 8443})
	if err != nil || decision.Allow {
		t.Fatalf("non-empty ports must override scalar port: decision=%+v err=%v", decision, err)
	}
}
