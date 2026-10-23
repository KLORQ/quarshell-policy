package policy

import (
	"strings"
	"testing"
)

func typed(t *testing.T, source string) *Policy {
	t.Helper()
	document, err := Parse(strings.NewReader(source), DefaultLimits())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	result, err := document.Typed()
	if err != nil {
		t.Fatalf("Typed: %v", err)
	}
	return result
}

func TestTypedNestedPolicy(t *testing.T) {
	source := `version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib]
  read_write: [/workspace]
process:
  run_as_user: sandbox
network_policies:
  api:
    name: api
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        access: read-only
        rules:
          - allow:
              method: GET
              path: /v1/*
    binaries:
      - path: /usr/bin/curl
`
	result := typed(t, source)
	if !result.Filesystem.HasValue() {
		t.Fatalf("filesystem absent")
	}
	filesystem := result.Filesystem.Value
	if len(filesystem.ReadOnly) != 2 || len(filesystem.ReadWrite) != 1 {
		t.Fatalf("filesystem = %+v", filesystem)
	}
	if !result.Process.HasValue() || result.Process.Value.RunAsUser.OrElse("") != "sandbox" {
		t.Fatalf("process = %+v", result.Process)
	}
	policies := result.NetworkPolicies.Value
	rule, ok := policies["api"]
	if !ok || len(rule.Endpoints) != 1 || len(rule.Binaries) != 1 {
		t.Fatalf("rule = %+v", rule)
	}
	endpoint := rule.Endpoints[0]
	if endpoint.Host != "api.example.com" || endpoint.Port.OrElse(0) != 443 {
		t.Fatalf("endpoint = %+v", endpoint)
	}
	if len(endpoint.Rules) != 1 || endpoint.Rules[0].Allow.Method != "GET" {
		t.Fatalf("rules = %+v", endpoint.Rules)
	}
}

func TestTypedPreservesPresence(t *testing.T) {
	result := typed(t, "version: 1\n")
	if result.Filesystem.IsAbsent() == false {
		t.Fatalf("filesystem must be absent")
	}
	if result.NetworkPolicies.HasValue() {
		t.Fatalf("network policies must be absent")
	}
}

func TestTypedRejectsBadPort(t *testing.T) {
	source := `version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        port: "443"
`
	document, err := Parse(strings.NewReader(source), DefaultLimits())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := document.Typed(); err == nil {
		t.Fatalf("string port must be rejected")
	}
}

func TestTypedMCPPresence(t *testing.T) {
	source := `version: 1
network_policies:
  mcp:
    endpoints:
      - host: mcp.example.com
        port: 443
        protocol: mcp
        mcp:
          versions: [2025-06-18]
          max_body_bytes: 1024
          strict_tool_names: false
`
	result := typed(t, source)
	endpoint := result.NetworkPolicies.Value["mcp"].Endpoints[0]
	if !endpoint.MCP.HasValue() {
		t.Fatalf("mcp absent")
	}
	mcp := endpoint.MCP.Value
	if !mcp.Versions.HasValue() || len(mcp.Versions.Value) != 1 {
		t.Fatalf("versions = %+v", mcp.Versions)
	}
	if !mcp.StrictToolNames.HasValue() || mcp.StrictToolNames.Value {
		t.Fatalf("strict_tool_names presence lost: %+v", mcp.StrictToolNames)
	}
	if mcp.MaxBodyBytes != 1024 {
		t.Fatalf("max body = %d", mcp.MaxBodyBytes)
	}
}
