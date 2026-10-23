package policy

import "testing"

func TestEvaluateQueryMatchers(t *testing.T) {
	policy := typed(t, `version: 1
network_policies:
  search:
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        rules:
          - allow:
              method: GET
              path: /search
              query:
                repo: NVIDIA/*
                tag:
                  any: [prod-*, staging-*]
`)
	cases := []struct {
		name  string
		query map[string]string
		want  Effect
	}{
		{"glob", map[string]string{"repo": "NVIDIA/x", "tag": "prod-a"}, EffectAllow},
		{"any", map[string]string{"repo": "NVIDIA/x", "tag": "staging-a"}, EffectAllow},
		{"glob mismatch", map[string]string{"repo": "evil/x", "tag": "prod-a"}, EffectDeny},
		{"any mismatch", map[string]string{"repo": "NVIDIA/x", "tag": "dev-a"}, EffectDeny},
		{"missing key", map[string]string{"repo": "NVIDIA/x"}, EffectDeny},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := policy.EvaluateNetwork(NetworkRequest{Host: "api.example.com", Port: 443, Protocol: "rest", Method: "GET", Path: "/search", Query: test.query})
			if got.Effect != test.want {
				t.Fatalf("effect = %s (%s), want %s", got.Effect, got.Reason, test.want)
			}
		})
	}
}

func TestEvaluateGraphQLRules(t *testing.T) {
	policy := typed(t, `version: 1
network_policies:
  graphql:
    endpoints:
      - host: api.example.com
        port: 443
        protocol: graphql
        rules:
          - allow:
              operation_type: query
              operation_name: RepoLookup
              fields: [repository, viewer]
`)
	cases := []struct {
		name string
		req  NetworkRequest
		want Effect
	}{
		{"allowed", NetworkRequest{Host: "api.example.com", Port: 443, Protocol: "graphql", OperationType: "query", OperationName: "RepoLookup", Fields: []string{"repository"}}, EffectAllow},
		{"unlisted field", NetworkRequest{Host: "api.example.com", Port: 443, Protocol: "graphql", OperationType: "query", OperationName: "RepoLookup", Fields: []string{"adminAuditLog"}}, EffectDeny},
		{"wrong operation", NetworkRequest{Host: "api.example.com", Port: 443, Protocol: "graphql", OperationType: "mutation", OperationName: "RepoLookup"}, EffectDeny},
		{"wrong name", NetworkRequest{Host: "api.example.com", Port: 443, Protocol: "graphql", OperationType: "query", OperationName: "Other"}, EffectDeny},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := policy.EvaluateNetwork(test.req); got.Effect != test.want {
				t.Fatalf("effect = %s (%s), want %s", got.Effect, got.Reason, test.want)
			}
		})
	}
}

func TestEvaluateMCPToolAndParams(t *testing.T) {
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
              tool: read_*
              params:
                name: read_file
`)
	cases := []struct {
		name string
		req  NetworkRequest
		want Effect
	}{
		{"tool and name", NetworkRequest{Host: "mcp.example.com", Port: 443, Protocol: "mcp", Method: "tools/call", Tool: "read_file", Params: map[string]any{"name": "read_file"}}, EffectAllow},
		{"tool glob", NetworkRequest{Host: "mcp.example.com", Port: 443, Protocol: "mcp", Method: "tools/call", Tool: "read_dir", Params: map[string]any{"name": "read_file"}}, EffectAllow},
		{"tool mismatch", NetworkRequest{Host: "mcp.example.com", Port: 443, Protocol: "mcp", Method: "tools/call", Tool: "write_file", Params: map[string]any{"name": "read_file"}}, EffectDeny},
		{"name mismatch", NetworkRequest{Host: "mcp.example.com", Port: 443, Protocol: "mcp", Method: "tools/call", Tool: "read_file", Params: map[string]any{"name": "write_file"}}, EffectDeny},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := policy.EvaluateNetwork(test.req); got.Effect != test.want {
				t.Fatalf("effect = %s (%s), want %s", got.Effect, got.Reason, test.want)
			}
		})
	}
}

func TestEvaluateSQLAndJSONRPC(t *testing.T) {
	sqlPolicy := typed(t, `version: 1
network_policies:
  db:
    endpoints:
      - host: db.example.com
        port: 5432
        protocol: sql
        enforcement: audit
        rules:
          - allow:
              command: SELECT
`)
	if got := sqlPolicy.EvaluateNetwork(NetworkRequest{Host: "db.example.com", Port: 5432, Protocol: "sql", Command: "SELECT"}); got.Effect != EffectAllow {
		t.Fatalf("SQL allow = %s (%s)", got.Effect, got.Reason)
	}
	if got := sqlPolicy.EvaluateNetwork(NetworkRequest{Host: "db.example.com", Port: 5432, Protocol: "sql", Command: "DROP"}); got.Effect != EffectDeny {
		t.Fatalf("SQL deny = %s (%s)", got.Effect, got.Reason)
	}

	rpcPolicy := typed(t, `version: 1
network_policies:
  rpc:
    endpoints:
      - host: rpc.example.com
        port: 443
        protocol: json-rpc
        rules:
          - allow:
              method: reports.search
`)
	if got := rpcPolicy.EvaluateNetwork(NetworkRequest{Host: "rpc.example.com", Port: 443, Protocol: "json-rpc", Method: "reports.search"}); got.Effect != EffectAllow {
		t.Fatalf("JSON-RPC allow = %s (%s)", got.Effect, got.Reason)
	}
	if got := rpcPolicy.EvaluateNetwork(NetworkRequest{Host: "rpc.example.com", Port: 443, Protocol: "json-rpc", Method: "reports.delete"}); got.Effect != EffectDeny {
		t.Fatalf("JSON-RPC deny = %s (%s)", got.Effect, got.Reason)
	}
}

func TestEvaluateAccessPresets(t *testing.T) {
	readOnly := typed(t, `version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        access: read-only
`)
	if got := readOnly.EvaluateNetwork(NetworkRequest{Host: "api.example.com", Port: 443, Protocol: "rest", Method: "GET", Path: "/"}); got.Effect != EffectAllow {
		t.Fatalf("read-only GET = %s (%s)", got.Effect, got.Reason)
	}
	if got := readOnly.EvaluateNetwork(NetworkRequest{Host: "api.example.com", Port: 443, Protocol: "rest", Method: "POST", Path: "/"}); got.Effect != EffectDeny {
		t.Fatalf("read-only POST = %s (%s)", got.Effect, got.Reason)
	}
	readWrite := typed(t, `version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        access: read-write
`)
	if got := readWrite.EvaluateNetwork(NetworkRequest{Host: "api.example.com", Port: 443, Protocol: "rest", Method: "PUT", Path: "/"}); got.Effect != EffectAllow {
		t.Fatalf("read-write PUT = %s (%s)", got.Effect, got.Reason)
	}
	if got := readWrite.EvaluateNetwork(NetworkRequest{Host: "api.example.com", Port: 443, Protocol: "rest", Method: "DELETE", Path: "/"}); got.Effect != EffectDeny {
		t.Fatalf("read-write DELETE = %s (%s)", got.Effect, got.Reason)
	}
}
