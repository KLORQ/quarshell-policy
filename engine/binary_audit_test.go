package engine_test

import (
	"context"
	"testing"

	"github.com/KLORQ/quarshell-policy/corepolicy"
	"github.com/KLORQ/quarshell-policy/engine"
)

func TestBinaryScopedRule(t *testing.T) {
	doc := policy.Document{Version: 1}
	doc.SetNetworkAllows([]policy.AllowRule{{
		ID: "curl-only", Host: "example.com", Port: 443,
		Binaries: []string{"/usr/bin/curl"},
	}})
	eng := &engine.Allowlist{}
	if err := eng.Apply(doc); err != nil {
		t.Fatal(err)
	}
	d, _ := eng.Decide(context.Background(), engine.EgressRequest{Host: "example.com", Port: 443, Binary: "/usr/bin/curl"})
	if !d.Allow {
		t.Fatalf("curl should allow: %s", d.Reason)
	}
	d, _ = eng.Decide(context.Background(), engine.EgressRequest{Host: "example.com", Port: 443, Binary: "/usr/bin/wget"})
	if d.Allow {
		t.Fatal("wget should deny")
	}
	d, _ = eng.Decide(context.Background(), engine.EgressRequest{Host: "example.com", Port: 443})
	if d.Allow || d.Reason != "binary_unknown" {
		t.Fatalf("empty binary must deny scoped rule: %+v", d)
	}
	d, _ = eng.DecideHTTP(context.Background(), engine.HTTPRequest{Host: "example.com", Port: 443, Method: "GET", Path: "/"})
	if d.Allow || d.Reason != "binary_unknown" {
		t.Fatalf("empty binary must deny scoped HTTP rule: %+v", d)
	}
}

func TestTopLevelBinaryUnknownFailsClosed(t *testing.T) {
	doc := policy.Document{Version: 1, Binaries: []string{"/usr/bin/curl"}}
	doc.SetNetworkAllows([]policy.AllowRule{{ID: "api", Host: "example.com", Port: 443}})
	eng := &engine.Allowlist{}
	if err := eng.Apply(doc); err != nil {
		t.Fatal(err)
	}
	d, _ := eng.Decide(context.Background(), engine.EgressRequest{Host: "example.com", Port: 443})
	if d.Allow || d.Reason != "binary_unknown: required by policy.binaries" {
		t.Fatalf("top-level binary restriction must deny unknown caller: %+v", d)
	}
}

func TestUnscopedRuleStillMatchesUnknownBinary(t *testing.T) {
	doc := policy.Document{Version: 1}
	doc.SetNetworkAllows([]policy.AllowRule{
		{ID: "scoped", Host: "example.com", Port: 443, Binaries: []string{"/usr/bin/curl"}},
		{ID: "public", Host: "example.com", Port: 443},
	})
	eng := &engine.Allowlist{}
	if err := eng.Apply(doc); err != nil {
		t.Fatal(err)
	}
	d, _ := eng.Decide(context.Background(), engine.EgressRequest{Host: "example.com", Port: 443})
	if !d.Allow || d.Matched == nil || d.Matched.ID != "public" {
		t.Fatalf("unscoped rule should match unknown caller: %+v", d)
	}
}

func TestBinaryGlobRecursive(t *testing.T) {
	doc := policy.Document{Version: 1}
	doc.SetNetworkAllows([]policy.AllowRule{{
		ID: "cursor", Host: "api2.cursor.sh", Port: 443,
		Binaries:       []string{"/opt/cursor-agent/**"},
		CredentialKeys: []string{"CURSOR_API_KEY"},
		Protocol:       "rest", TLS: "terminate", Access: "read-write",
	}})
	eng := &engine.Allowlist{}
	if err := eng.Apply(doc); err != nil {
		t.Fatal(err)
	}
	node := "/opt/cursor-agent/versions/2026.09.10-fd3934a/node"
	d, _ := eng.Decide(context.Background(), engine.EgressRequest{Host: "api2.cursor.sh", Port: 443, Binary: node})
	if !d.Allow {
		t.Fatalf("node under /opt/cursor-agent/** should allow: %s", d.Reason)
	}
	if d.Matched == nil || len(d.Matched.Rule.CredentialKeys) == 0 {
		t.Fatal("expected credential-bound rule")
	}
}

func TestAuditEnforcementL7(t *testing.T) {
	doc := policy.Document{Version: 1}
	doc.SetNetworkAllows([]policy.AllowRule{{
		ID: "ro", Host: "api.example.com", Port: 80,
		Protocol: "rest", Access: "read-only", Enforcement: "audit",
	}})
	eng := &engine.Allowlist{}
	if err := eng.Apply(doc); err != nil {
		t.Fatal(err)
	}
	d, _ := eng.DecideHTTP(context.Background(), engine.HTTPRequest{
		Host: "api.example.com", Port: 80, Method: "POST", Path: "/v1",
	})
	if !d.Allow || !d.Audit {
		t.Fatalf("expected audit allow, got allow=%v audit=%v reason=%s", d.Allow, d.Audit, d.Reason)
	}
	d, _ = eng.DecideHTTP(context.Background(), engine.HTTPRequest{
		Host: "api.example.com", Port: 80, Method: "GET", Path: "/v1",
	})
	if !d.Allow || d.Audit {
		t.Fatalf("GET should clean allow, got allow=%v audit=%v", d.Allow, d.Audit)
	}
}
