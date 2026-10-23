package policy_test

import (
	"context"
	"strings"
	"testing"

	"github.com/KLORQ/quarshell-policy/corepolicy"
	"github.com/KLORQ/quarshell-policy/engine"
)

func TestCompatSQLAuditConfigAndCommandSelectors(t *testing.T) {
	doc, err := policy.Parse([]byte(`version: 1
network_policies:
  database:
    endpoints:
      - host: db.example.com
        port: 5432
        protocol: sql
        enforcement: audit
        rules:
          - allow: {command: SELECT}
          - allow: {command: INSERT}
        deny_rules:
          - command: DROP
`))
	if err != nil {
		t.Fatal(err)
	}
	if err = doc.Validate(); err != nil {
		t.Fatal(err)
	}
	rule := doc.NetworkAllows()[0]
	for _, tc := range []struct {
		command string
		allowed bool
	}{
		{"select", true}, {"INSERT", true}, {"DROP", false}, {"UPDATE", false},
	} {
		got, _ := rule.MatchSQLCommand(tc.command)
		if got != tc.allowed {
			t.Fatalf("command %q allowed=%v want=%v", tc.command, got, tc.allowed)
		}
	}
	wildcard := rule
	wildcard.Rules = []policy.L7Rule{{Allow: &policy.L7Allow{Command: "*"}}}
	wildcard.DenyRules = nil
	if ok, _ := wildcard.MatchSQLCommand("anything"); !ok {
		t.Fatal("SQL command wildcard did not match")
	}
	eng := &engine.Allowlist{}
	if err = eng.Apply(doc); err != nil {
		t.Fatal(err)
	}
	decision, err := eng.Decide(context.Background(), engine.EgressRequest{Host: "db.example.com", Port: 5432})
	if err != nil || !decision.Allow || !decision.Audit || !strings.Contains(decision.Reason, "inspection is unavailable") {
		t.Fatalf("SQL pass-through decision=%+v err=%v", decision, err)
	}
}

func TestCompatSQLAndTCPValidation(t *testing.T) {
	base := `version: 1
network_policies:
  db:
    endpoints:
      - host: db.example.com
        port: 5432
        protocol: sql
        enforcement: %s
        rules:
          - allow: {command: SELECT}
`
	for _, tc := range []struct {
		enforcement string
		valid       bool
	}{{"audit", true}, {"enforce", false}, {"", false}} {
		doc, err := policy.Parse([]byte(strings.Replace(base, "%s", tc.enforcement, 1)))
		if err != nil {
			t.Fatal(err)
		}
		err = doc.Validate()
		if (err == nil) != tc.valid {
			t.Fatalf("enforcement=%q err=%v", tc.enforcement, err)
		}
	}
	tcp, err := policy.Parse([]byte(`version: 1
network_policies:
  tcp:
    endpoints:
      - host: tcp.example.com
        port: 9000
        protocol: tcp
`))
	if err != nil {
		t.Fatal(err)
	}
	if err = tcp.Validate(); err != nil {
		t.Fatal(err)
	}
	tcp.NetworkPolicies["tcp"] = policy.NetworkPolicy{Endpoints: []policy.AllowRule{{Host: "tcp.example.com", Port: 9000, Protocol: "tcp", Rules: []policy.L7Rule{{Allow: &policy.L7Allow{Command: "SELECT"}}}}}}
	if err = tcp.Validate(); err == nil {
		t.Fatal("explicit TCP marker must reject L7 rules")
	}
}
