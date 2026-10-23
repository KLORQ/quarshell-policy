package policy

import "testing"

const evaluatorPolicy = `version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib]
  read_write: [/workspace]
process:
  run_as_user: sandbox
  run_as_group: sandbox
network_policies:
  api:
    endpoints:
      - host: '**.example.com'
        port: 443
        protocol: rest
        rules:
          - allow:
              method: GET
              path: /v1/*
        deny_rules:
          - method: DELETE
            path: /v1/secret
  tcp:
    endpoints:
      - host: db.internal
        port: 5432
        protocol: tcp
`

func evaluator(t *testing.T) *Policy {
	t.Helper()
	return typed(t, evaluatorPolicy)
}

func TestEvaluateFilesystem(t *testing.T) {
	policy := evaluator(t)
	cases := []struct {
		name    string
		request FilesystemRequest
		effect  Effect
	}{
		{"read usr", FilesystemRequest{Path: "/usr/bin/curl", Access: AccessRead}, EffectAllow},
		{"exec usr", FilesystemRequest{Path: "/usr/bin/curl", Access: AccessExec}, EffectAllow},
		{"read etc", FilesystemRequest{Path: "/etc/passwd", Access: AccessRead}, EffectDeny},
		{"write workspace", FilesystemRequest{Path: "/workspace/a.txt", Access: AccessWrite}, EffectAllow},
		{"write usr", FilesystemRequest{Path: "/usr/a.txt", Access: AccessWrite}, EffectDeny},
		{"traversal", FilesystemRequest{Path: "/usr/../etc/passwd", Access: AccessRead}, EffectDeny},
		{"workdir write", FilesystemRequest{Path: "/home/agent/repo/a", Access: AccessWrite, Workdir: "/home/agent/repo"}, EffectAllow},
		{"unknown access", FilesystemRequest{Path: "/workspace/a", Access: "chmod"}, EffectUnsupported},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := policy.EvaluateFilesystem(test.request); got.Effect != test.effect {
				t.Fatalf("effect = %s (%s), want %s", got.Effect, got.Reason, test.effect)
			}
		})
	}
}

func TestEvaluatePortsListOverridesSinglePort(t *testing.T) {
	policy := typed(t, `version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        port: 80
        ports: [443]
        protocol: rest
        access: full
`)
	if got := policy.EvaluateNetwork(NetworkRequest{Host: "api.example.com", Port: 443, Protocol: "rest", Method: "GET", Path: "/"}); got.Effect != EffectAllow {
		t.Fatalf("ports list was not used: %s (%s)", got.Effect, got.Reason)
	}
	if got := policy.EvaluateNetwork(NetworkRequest{Host: "api.example.com", Port: 80, Protocol: "rest", Method: "GET", Path: "/"}); got.Effect != EffectDeny {
		t.Fatalf("single port overrode ports list: %s (%s)", got.Effect, got.Reason)
	}
}

func TestEvaluateProcess(t *testing.T) {
	policy := evaluator(t)
	if got := policy.EvaluateProcess(ProcessRequest{User: "sandbox", Group: "sandbox"}); got.Effect != EffectAllow {
		t.Fatalf("matching identity denied: %s", got.Reason)
	}
	if got := policy.EvaluateProcess(ProcessRequest{User: "root", Group: "sandbox"}); got.Effect != EffectDeny {
		t.Fatalf("wrong user allowed")
	}
	if got := policy.EvaluateProcess(ProcessRequest{User: "sandbox", Group: "root"}); got.Effect != EffectDeny {
		t.Fatalf("wrong group allowed")
	}
}

func TestEvaluateNetwork(t *testing.T) {
	policy := evaluator(t)
	cases := []struct {
		name    string
		request NetworkRequest
		effect  Effect
	}{
		{"allowed GET", NetworkRequest{Host: "api.example.com", Port: 443, Protocol: "rest", Method: "GET", Path: "/v1/models"}, EffectAllow},
		{"denied POST", NetworkRequest{Host: "api.example.com", Port: 443, Protocol: "rest", Method: "POST", Path: "/v1/models"}, EffectDeny},
		{"deny rule wins", NetworkRequest{Host: "api.example.com", Port: 443, Protocol: "rest", Method: "DELETE", Path: "/v1/secret"}, EffectDeny},
		{"wrong host", NetworkRequest{Host: "evil.example.net", Port: 443, Protocol: "rest", Method: "GET", Path: "/v1/models"}, EffectDeny},
		{"wrong port", NetworkRequest{Host: "api.example.com", Port: 80, Protocol: "rest", Method: "GET", Path: "/v1/models"}, EffectDeny},
		{"tcp endpoint", NetworkRequest{Host: "db.internal", Port: 5432, Protocol: "tcp"}, EffectAllow},
		{"protocol mismatch", NetworkRequest{Host: "api.example.com", Port: 443, Protocol: "graphql", Method: "POST", Path: "/graphql"}, EffectDeny},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := policy.EvaluateNetwork(test.request); got.Effect != test.effect {
				t.Fatalf("effect = %s (%s), want %s", got.Effect, got.Reason, test.effect)
			}
		})
	}
}

func TestEvaluateNetworkUnsupportedProtocol(t *testing.T) {
	policy := typed(t, `version: 1
network_policies:
  ftp:
    endpoints:
      - host: ftp.example.com
        port: 21
        protocol: ftp
`)
	got := policy.EvaluateNetwork(NetworkRequest{Host: "ftp.example.com", Port: 21, Protocol: "ftp"})
	if got.Effect != EffectUnsupported {
		t.Fatalf("effect = %s (%s), want unsupported", got.Effect, got.Reason)
	}
}

func TestEvaluateNetworkUnsupportedMatcher(t *testing.T) {
	policy := typed(t, `version: 1
network_policies:
  mcp:
    endpoints:
      - host: mcp.example.com
        port: 443
        protocol: mcp
        rules:
          - allow:
              method: tools/call
              params:
                arguments:
                  repo: NVIDIA/*
`)
	got := policy.EvaluateNetwork(NetworkRequest{
		Host: "mcp.example.com", Port: 443, Protocol: "mcp", Method: "tools/call",
		Params: map[string]any{"arguments": map[string]any{"repo": "NVIDIA/x"}},
	})
	if got.Effect != EffectUnsupported {
		t.Fatalf("effect = %s (%s), want unsupported", got.Effect, got.Reason)
	}
}

func TestEvaluateGlob(t *testing.T) {
	cases := []struct {
		pattern string
		value   string
		sep     rune
		want    bool
	}{
		{"**.example.com", "api.example.com", '.', true},
		{"*.example.com", "api.example.com", '.', true},
		{"*.example.com", "a.b.example.com", '.', false},
		{"/v1/*", "/v1/models", '/', true},
		{"/v1/*", "/v1/a/b", '/', false},
		{"/v1/**", "/v1/a/b", '/', true},
	}
	for _, test := range cases {
		if got := globMatch(test.pattern, test.value, test.sep); got != test.want {
			t.Fatalf("globMatch(%q, %q) = %v", test.pattern, test.value, got)
		}
	}
}
