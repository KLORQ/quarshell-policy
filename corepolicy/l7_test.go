package policy_test

import (
	"testing"

	"github.com/KLORQ/quarshell-policy/corepolicy"
)

func docWithAllows(rules ...policy.AllowRule) policy.Document {
	doc := policy.Document{Version: 1}
	doc.SetNetworkAllows(rules)
	return doc
}

func TestL7ValidateREST(t *testing.T) {
	doc := docWithAllows(policy.AllowRule{
		ID: "api", Host: "api.example.com", Port: 80, Protocol: "rest", Access: "read-only",
	})
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestL7ValidateHTTPSUsesTLSAutoDetection(t *testing.T) {
	for _, tlsMode := range []string{"", "terminate", "passthrough", "skip", "clear"} {
		t.Run(tlsMode, func(t *testing.T) {
			doc := docWithAllows(policy.AllowRule{
				Host: "api.example.com", Port: 443, Protocol: "rest", Access: "read-only", TLS: tlsMode,
			})
			if err := doc.Validate(); err != nil {
				t.Fatalf("Validate(): %v", err)
			}
		})
	}
}

func TestRequestBodyCredentialRewriteConstraints(t *testing.T) {
	base := policy.AllowRule{Host: "api.example.com", Port: 80, Protocol: "rest", Access: "read-write", RequestBodyCredentialRewrite: true}
	if err := docWithAllows(base).Validate(); err != nil {
		t.Fatalf("REST body rewrite should validate: %v", err)
	}
	base.Protocol = "graphql"
	if err := docWithAllows(base).Validate(); err == nil {
		t.Fatal("body credential rewrite must be REST-only")
	}
	base.Protocol = "rest"
	base.CredentialSigning = "sigv4"
	if err := docWithAllows(base).Validate(); err == nil {
		t.Fatal("body rewrite and credential signing must be mutually exclusive")
	}
}

func TestJSONRPCPolicyRequiresExactMethodRules(t *testing.T) {
	rule := policy.AllowRule{
		Host: "rpc.example.com", Port: 443, Protocol: policy.ProtocolJSONRPC, TLS: policy.TLSTerminate,
		Rules: []policy.L7Rule{{Allow: &policy.L7Allow{Method: "chain_getBlock"}}},
	}
	if err := docWithAllows(rule).Validate(); err != nil {
		t.Fatal(err)
	}
	if ok, _ := rule.MatchHTTP("chain_getBlock", "/rpc"); !ok {
		t.Fatal("exact JSON-RPC method should be allowed")
	}
	if ok, _ := rule.MatchHTTP("chain_getHead", "/rpc"); ok {
		t.Fatal("unlisted JSON-RPC method should be denied")
	}
	if ok, _ := rule.MatchHTTP(" chain_getBlock ", "/rpc"); ok {
		t.Fatal("JSON-RPC method matching must preserve exact method names")
	}
	rule.Rules[0].Allow.Method = "chain_*"
	if err := docWithAllows(rule).Validate(); err == nil {
		t.Fatal("JSON-RPC method glob should be rejected")
	}
	rule.Rules[0].Allow.Method = "chain_getBlock"
	rule.Access = policy.AccessFull
	if err := docWithAllows(rule).Validate(); err == nil {
		t.Fatal("JSON-RPC access presets should be rejected")
	}
}

func TestGraphQLOperationSelectorsAndPersistedRegistry(t *testing.T) {
	rule := policy.AllowRule{
		Host: "gql.example", Port: 443, Protocol: policy.ProtocolGraphQL, TLS: policy.TLSTerminate,
		Rules:     []policy.L7Rule{{Allow: &policy.L7Allow{OperationType: "query", OperationName: "Dash*", Fields: []string{"public*"}}}},
		DenyRules: []policy.L7DenyRule{{OperationType: "query", Fields: []string{"publicAdmin"}}},
	}
	if err := docWithAllows(rule).Validate(); err != nil {
		t.Fatal(err)
	}
	op := policy.GraphQLOperation{OperationType: "query", OperationName: "Dashboard", Fields: []string{"publicStatus", "publicProfile"}}
	if ok, _ := rule.MatchGraphQLOperation(op, "/graphql"); !ok {
		t.Fatal("matching query and all matching fields should allow")
	}
	op.Fields = append(op.Fields, "privateAdmin")
	if ok, _ := rule.MatchGraphQLOperation(op, "/graphql"); ok {
		t.Fatal("allow rule must match every root field")
	}
	op.Fields = []string{"publicAdmin"}
	if ok, _ := rule.MatchGraphQLOperation(op, "/graphql"); ok {
		t.Fatal("matching deny rule must take precedence")
	}

	rule.PersistedQueries = "allow_registered"
	rule.GraphQLPersistedQueries = map[string]policy.GraphQLOperationDef{
		"abc": {OperationType: "query", OperationName: "Dashboard", Fields: []string{"publicStatus"}},
	}
	if err := docWithAllows(rule).Validate(); err != nil {
		t.Fatal(err)
	}
	persisted := policy.GraphQLOperation{Persisted: true, PersistedQueryHash: "abc"}
	if ok, _ := rule.MatchGraphQLOperation(persisted, "/graphql"); !ok {
		t.Fatal("registered hash-only operation should use registry metadata")
	}
	persisted.PersistedQueryHash = "unknown"
	if ok, _ := rule.MatchGraphQLOperation(persisted, "/graphql"); ok {
		t.Fatal("unregistered hash-only operation must fail closed")
	}
}

func TestL7MatchHTTP(t *testing.T) {
	rule := policy.AllowRule{
		Host: "api.example.com", Port: 80, Protocol: "rest", Access: "read-only",
	}
	ok, _ := rule.MatchHTTP("GET", "/v1/x")
	if !ok {
		t.Fatal("GET should allow")
	}
	ok, _ = rule.MatchHTTP("POST", "/v1/x")
	if ok {
		t.Fatal("POST should deny on read-only")
	}
}

func TestWebsocketPolicyValidate(t *testing.T) {
	doc := docWithAllows(policy.AllowRule{
		Host: "realtime.example.com", Port: 443, Protocol: "websocket", TLS: "terminate", Access: "read-write",
	})
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	allows := doc.NetworkAllows()[0].ExpandedL7Allows()
	if len(allows) != 2 {
		t.Fatalf("allows=%v", allows)
	}
}

func TestL7ExplicitRulesAndDeny(t *testing.T) {
	rule := policy.AllowRule{
		Host: "api.example.com", Port: 80, Protocol: "rest",
		Rules: []policy.L7Rule{
			{Allow: &policy.L7Allow{Method: "POST", Path: "/v1/chat"}},
			{Allow: &policy.L7Allow{Method: "GET", Path: "/v1/**"}},
		},
		DenyRules: []policy.L7DenyRule{
			{Method: "GET", Path: "/v1/admin/**"},
		},
	}
	doc := docWithAllows(rule)
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestMCPAllowAllKnownMethods(t *testing.T) {
	allowAll := true
	rule := policy.AllowRule{
		Host: "mcp.example.com", Port: 443, TLS: "terminate", Protocol: "mcp",
		MCP: &policy.MCPConfig{AllowAllKnownMCPMethods: &allowAll},
	}
	if err := docWithAllows(rule).Validate(); err != nil {
		t.Fatal(err)
	}
	if ok, _ := rule.MatchHTTP("tools/list", "/"); !ok {
		t.Fatal("MCP allow-all profile must allow known methods")
	}
	rule.DenyRules = []policy.L7DenyRule{{Method: "tools/call", Tool: &policy.QueryMatcher{Any: []string{"dangerous"}}}}
	if ok, _ := rule.MatchHTTP("tools/call", "/\x00dangerous"); ok {
		t.Fatal("explicit deny rule must override allow-all profile")
	}
}

func TestMCPRequiresMethodsUnlessAllowAllEnabled(t *testing.T) {
	rule := policy.AllowRule{Host: "mcp.example.com", Port: 443, TLS: "terminate", Protocol: "mcp"}
	if err := docWithAllows(rule).Validate(); err == nil {
		t.Fatal("MCP without methods must fail validation")
	}
	allowAll := true
	rule.MCP = &policy.MCPConfig{AllowAllKnownMCPMethods: &allowAll}
	if err := docWithAllows(rule).Validate(); err != nil {
		t.Fatal(err)
	}
}
