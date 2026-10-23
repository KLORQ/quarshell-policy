package policy

import (
	"path"
	"strings"
)

// L7 protocols accepted by OpenShell policy endpoints.
const (
	ProtocolREST      = "rest"
	ProtocolWebsocket = "websocket"
	ProtocolGraphQL   = "graphql"
	ProtocolSQL       = "sql"
	ProtocolTCP       = "tcp"
	ProtocolMCP       = "mcp"
	ProtocolJSONRPC   = "json-rpc"
)

// Deprecated TLS aliases retained from the OpenShell policy schema. Only
// "skip" disables automatic TLS inspection; these values resolve to Auto.
const (
	TLSTerminate   = "terminate"
	TLSPassthrough = "passthrough"
)

// Access presets expand into method/path allow rules.
const (
	AccessReadOnly  = "read-only"
	AccessReadWrite = "read-write"
	AccessFull      = "full"
)

// L7Rule wraps an allow rule.
type L7Rule struct {
	Allow *L7Allow `yaml:"allow,omitempty" json:"allow,omitempty"`
}

// L7Allow matches one HTTP, JSON-RPC, MCP, or GraphQL request.
type L7Allow struct {
	Command       string                  `yaml:"command,omitempty" json:"command,omitempty"`
	Query         map[string]QueryMatcher `yaml:"query,omitempty" json:"query,omitempty"`
	Method        string                  `yaml:"method,omitempty" json:"method,omitempty"`
	Path          string                  `yaml:"path,omitempty" json:"path,omitempty"`
	OperationType string                  `yaml:"operation_type,omitempty" json:"operation_type,omitempty"`
	OperationName string                  `yaml:"operation_name,omitempty" json:"operation_name,omitempty"`
	Fields        []string                `yaml:"fields,omitempty" json:"fields,omitempty"`
	// Tool matches MCP tools/call params.name. Nil means no constraint.
	Tool   *QueryMatcher           `yaml:"tool,omitempty" json:"tool,omitempty"`
	Params map[string]QueryMatcher `yaml:"params,omitempty" json:"params,omitempty"`
}

// L7DenyRule blocks matching requests (checked before allows).
type L7DenyRule struct {
	Command       string                  `yaml:"command,omitempty" json:"command,omitempty"`
	Query         map[string]QueryMatcher `yaml:"query,omitempty" json:"query,omitempty"`
	Method        string                  `yaml:"method,omitempty" json:"method,omitempty"`
	Path          string                  `yaml:"path,omitempty" json:"path,omitempty"`
	Tool          *QueryMatcher           `yaml:"tool,omitempty" json:"tool,omitempty"`
	Params        map[string]QueryMatcher `yaml:"params,omitempty" json:"params,omitempty"`
	OperationType string                  `yaml:"operation_type,omitempty" json:"operation_type,omitempty"`
	OperationName string                  `yaml:"operation_name,omitempty" json:"operation_name,omitempty"`
	Fields        []string                `yaml:"fields,omitempty" json:"fields,omitempty"`
}

// NeedsL7 reports whether the rule requires application-layer inspection.
func (r AllowRule) NeedsL7() bool {
	proto := strings.ToLower(strings.TrimSpace(r.Protocol))
	if proto == ProtocolSQL || proto == ProtocolTCP {
		return false // SQL inspection is unavailable in the pinned v1 runtime; TCP is L4.
	}
	if proto == "" {
		return false
	}
	if strings.TrimSpace(r.Access) != "" {
		return true
	}
	if len(r.Rules) > 0 || len(r.DenyRules) > 0 {
		return true
	}
	return proto == ProtocolREST || proto == ProtocolWebsocket || proto == ProtocolGraphQL || proto == ProtocolMCP || proto == ProtocolJSONRPC
}

// HasL7Policy reports whether any L7 policy settings were authored, even when
// the selected protocol is audit-only or explicitly L4.
func (r AllowRule) HasL7Policy() bool {
	return strings.EqualFold(strings.TrimSpace(r.Protocol), ProtocolSQL) || r.NeedsL7() || strings.TrimSpace(r.Access) != "" || len(r.Rules) > 0 || len(r.DenyRules) > 0
}

// MatchSQLCommand applies OpenShell command semantics for protocol sql.
// The runtime intentionally exposes this for policy adapters while the pinned
// supervisor keeps SQL audit-only until it has a SQL parser.
func (r AllowRule) MatchSQLCommand(command string) (bool, string) {
	if !strings.EqualFold(strings.TrimSpace(r.Protocol), ProtocolSQL) {
		return false, "SQL command policy used on a non-SQL endpoint"
	}
	for _, deny := range r.DenyRules {
		if commandMatches(command, deny.Command) {
			return false, "matched SQL deny rule"
		}
	}
	for _, allow := range r.Rules {
		if allow.Allow != nil && commandMatches(command, allow.Allow.Command) {
			return true, "matched SQL command allow"
		}
	}
	return false, "no matching SQL command allow"
}

func commandMatches(actual, expected string) bool {
	expected = strings.TrimSpace(expected)
	return expected != "" && (expected == "*" || strings.EqualFold(actual, expected))
}

// UsesGraphQLOperationRules reports whether a WebSocket endpoint carries
// GraphQL operation selectors in addition to its HTTP upgrade rules.
func (r AllowRule) UsesGraphQLOperationRules() bool {
	for _, rule := range r.Rules {
		if rule.Allow != nil && hasGraphQLSelectors(rule.Allow.OperationType, rule.Allow.OperationName, rule.Allow.Fields) {
			return true
		}
	}
	for _, rule := range r.DenyRules {
		if hasGraphQLSelectors(rule.OperationType, rule.OperationName, rule.Fields) {
			return true
		}
	}
	return false
}

// MethodWebsocketText is the synthetic L7 method for client→server WS text frames.
const MethodWebsocketText = "WEBSOCKET_TEXT"

// MethodSubscribe is the synthetic L7 method for GraphQL-over-WS subscribe/start.
const MethodSubscribe = "subscribe"

// ExpandedL7Allows returns explicit allow rules, expanding access presets when set.
// Endpoint Path scopes preset paths when non-empty.
func (r AllowRule) ExpandedL7Allows() []L7Allow {
	if len(r.Rules) > 0 {
		var out []L7Allow
		for _, rule := range r.Rules {
			if rule.Allow == nil {
				continue
			}
			a := *rule.Allow
			if a.Path == "" {
				a.Path = defaultL7Path(r.Path)
			}
			out = append(out, a)
		}
		return out
	}
	access := strings.ToLower(strings.TrimSpace(r.Access))
	if access == "" {
		if strings.EqualFold(strings.TrimSpace(r.Protocol), ProtocolMCP) && r.MCP != nil && r.MCP.AllowAllKnownMCPMethods != nil && *r.MCP.AllowAllKnownMCPMethods {
			return []L7Allow{{Method: "*", Path: defaultL7Path(r.Path)}}
		}
		return nil
	}
	basePath := defaultL7Path(r.Path)
	proto := strings.ToLower(strings.TrimSpace(r.Protocol))
	switch proto {
	case ProtocolWebsocket:
		switch access {
		case AccessReadOnly:
			return []L7Allow{{Method: "GET", Path: basePath}}
		case AccessReadWrite:
			return []L7Allow{
				{Method: "GET", Path: basePath},
				{Method: MethodWebsocketText, Path: basePath},
			}
		case AccessFull:
			return []L7Allow{{Method: "*", Path: basePath}}
		default:
			return nil
		}
	case ProtocolGraphQL:
		switch access {
		case AccessReadOnly:
			return []L7Allow{{OperationType: "query", Path: basePath}}
		case AccessReadWrite:
			return []L7Allow{
				{OperationType: "query", Path: basePath},
				{OperationType: "mutation", Path: basePath},
			}
		case AccessFull:
			return []L7Allow{{OperationType: "*", Path: basePath}}
		default:
			return nil
		}
	case ProtocolMCP:
		switch access {
		case AccessReadOnly:
			return []L7Allow{
				{Method: "initialize", Path: basePath},
				{Method: "tools/list", Path: basePath},
				{Method: "resources/list", Path: basePath},
				{Method: "resources/read", Path: basePath},
				{Method: "prompts/list", Path: basePath},
			}
		case AccessReadWrite:
			return []L7Allow{
				{Method: "initialize", Path: basePath},
				{Method: "tools/list", Path: basePath},
				{Method: "tools/call", Path: basePath},
				{Method: "resources/list", Path: basePath},
				{Method: "resources/read", Path: basePath},
				{Method: "prompts/list", Path: basePath},
			}
		case AccessFull:
			return []L7Allow{{Method: "*", Path: basePath}}
		default:
			return nil
		}
	}
	switch access {
	case AccessReadOnly:
		return []L7Allow{
			{Method: "GET", Path: basePath},
			{Method: "HEAD", Path: basePath},
			{Method: "OPTIONS", Path: basePath},
		}
	case AccessReadWrite:
		return []L7Allow{
			{Method: "GET", Path: basePath},
			{Method: "HEAD", Path: basePath},
			{Method: "OPTIONS", Path: basePath},
			{Method: "POST", Path: basePath},
			{Method: "PUT", Path: basePath},
			{Method: "PATCH", Path: basePath},
		}
	case AccessFull:
		return []L7Allow{{Method: "*", Path: basePath}}
	default:
		return nil
	}
}

// MatchGraphQLOperation enforces GraphQL operation selectors, including the
// pinned registered-operation semantics for hash-only persisted queries.
func (r AllowRule) MatchGraphQLOperation(operation GraphQLOperation, reqPath string) (bool, string) {
	return r.MatchGraphQLQuery(operation, reqPath, nil)
}

// MatchGraphQLQuery includes query selectors in GraphQL operation decisions.
func (r AllowRule) MatchGraphQLQuery(operation GraphQLOperation, reqPath string, query map[string][]string) (bool, string) {
	if !strings.EqualFold(strings.TrimSpace(r.Protocol), ProtocolGraphQL) && !strings.EqualFold(strings.TrimSpace(r.Protocol), ProtocolWebsocket) {
		return false, "graphql policy used on a non-GraphQL endpoint"
	}
	if !MatchL7Path(defaultL7Path(r.Path), reqPath) {
		return false, "graphql endpoint path mismatch"
	}
	if operation.Persisted && operation.OperationType == "" {
		if r.PersistedQueries != "allow_registered" {
			return false, "persisted GraphQL operation is not registered"
		}
		key := operation.PersistedQueryHash
		if key == "" {
			key = operation.PersistedQueryID
		}
		registered, ok := r.GraphQLPersistedQueries[key]
		if !ok || registered.OperationType == "" {
			return false, "persisted GraphQL operation is not registered"
		}
		operation.OperationType = registered.OperationType
		operation.OperationName = registered.OperationName
		operation.Fields = registered.Fields
	}
	for _, deny := range r.DenyRules {
		if graphQLOperationMatches(operation, deny.OperationType, deny.OperationName, deny.Fields) && MatchL7Path(defaultL7Path(deny.Path), reqPath) && matchQuery(deny.Query, query, true) {
			return false, "matched GraphQL deny rule"
		}
	}
	for _, allow := range r.ExpandedL7Allows() {
		if graphQLOperationMatches(operation, allow.OperationType, allow.OperationName, allow.Fields) && MatchL7Path(defaultL7Path(allow.Path), reqPath) && matchQuery(allow.Query, query, false) {
			return true, "matched GraphQL operation rule"
		}
	}
	return false, "no matching GraphQL operation rule"
}

func graphQLOperationMatches(op GraphQLOperation, operationType, operationName string, fieldPatterns []string) bool {
	if operationType == "" || (operationType != "*" && !strings.EqualFold(operationType, op.OperationType)) {
		return false
	}
	if operationName != "" {
		matched, err := path.Match(operationName, op.OperationName)
		if err != nil || !matched {
			return false
		}
	}
	if len(fieldPatterns) == 0 {
		return true
	}
	if len(op.Fields) == 0 {
		return false
	}
	for _, field := range op.Fields {
		matched := false
		for _, pattern := range fieldPatterns {
			if ok, err := path.Match(pattern, field); err == nil && ok {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func defaultL7Path(endpointPath string) string {
	p := strings.TrimSpace(endpointPath)
	if p == "" {
		return "/**"
	}
	return p
}

// MatchL7Path matches an HTTP path against a policy glob (* = one segment, ** = any).
func MatchL7Path(pattern, reqPath string) bool {
	pat := normalizeURLPath(pattern)
	p := normalizeURLPath(reqPath)
	if pat == "/**" || pat == "**" {
		return true
	}
	return matchPathGlob(pat, p)
}

func normalizeURLPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	// Keep trailing semantics soft: Clean collapses // and .
	clean := path.Clean(p)
	if strings.HasSuffix(p, "/") && clean != "/" {
		return clean + "/"
	}
	return clean
}

func matchPathGlob(pattern, req string) bool {
	if pattern == req {
		return true
	}
	if !strings.Contains(pattern, "**") {
		ok, err := path.Match(pattern, req)
		return err == nil && ok
	}
	// Memoized matching keeps repeated ** bounded by len(pattern)*len(req).
	type position struct{ pat, value int }
	seen := map[position]bool{}
	memo := map[position]bool{}
	var match func(int, int) bool
	match = func(i, j int) bool {
		pos := position{i, j}
		if seen[pos] {
			return memo[pos]
		}
		seen[pos] = true
		if i == len(pattern) {
			memo[pos] = j == len(req)
			return memo[pos]
		}
		switch pattern[i] {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				memo[pos] = match(i+2, j) || (j < len(req) && match(i, j+1))
			} else {
				memo[pos] = match(i+1, j) || (j < len(req) && req[j] != '/' && match(i, j+1))
			}
		case '?':
			memo[pos] = j < len(req) && req[j] != '/' && match(i+1, j+1)
		default:
			memo[pos] = j < len(req) && pattern[i] == req[j] && match(i+1, j+1)
		}
		return memo[pos]
	}
	return match(0, 0)
}

// MatchHTTP reports whether method+path is allowed under this rule's L7 policy.
// L4-only rules (no L7) allow any method/path.
// For MCP, method is the JSON-RPC method and reqPath may be "method\x00tool".
func (r AllowRule) MatchHTTP(method, reqPath string) (allow bool, reason string) {
	return r.MatchHTTPQuery(method, reqPath, nil)
}

// MatchHTTPQuery authorizes a request with decoded, repeated query values.
func (r AllowRule) MatchHTTPQuery(method, reqPath string, query map[string][]string) (allow bool, reason string) {
	if !r.NeedsL7() {
		return true, "l4-only"
	}
	protocol := strings.TrimSpace(r.Protocol)
	if !strings.EqualFold(protocol, ProtocolJSONRPC) {
		method = strings.TrimSpace(method)
	}
	tool := ""
	pathOnly := reqPath
	if strings.EqualFold(protocol, ProtocolJSONRPC) {
		if before, _, ok := strings.Cut(reqPath, "\x00"); ok {
			pathOnly = before
		}
		if pathOnly == "" {
			pathOnly = defaultL7Path(r.Path)
		}
	} else if strings.EqualFold(strings.TrimSpace(r.Protocol), ProtocolMCP) {
		method = strings.TrimSpace(method)
		if before, after, ok := strings.Cut(reqPath, "\x00"); ok {
			pathOnly = before
			tool = after
		}
		if pathOnly == "" {
			pathOnly = defaultL7Path(r.Path)
		}
	} else {
		method = strings.ToUpper(method)
	}
	for _, d := range r.DenyRules {
		if mcpOrHTTPMethodMatch(r.Protocol, d.Method, method) && MatchL7Path(defaultL7Path(d.Path), pathOnly) && matchToolSelector(d.Tool, d.Params, tool) && matchQuery(d.Query, query, true) {
			return false, "matched deny_rules"
		}
	}
	allows := r.ExpandedL7Allows()
	if len(allows) == 0 {
		return false, "l7 configured but no allow rules"
	}
	for _, a := range allows {
		if mcpOrHTTPMethodMatch(r.Protocol, a.Method, method) && MatchL7Path(defaultL7Path(a.Path), pathOnly) && matchToolSelector(a.Tool, a.Params, tool) && matchQuery(a.Query, query, false) {
			return true, "matched l7 allow"
		}
	}
	return false, "no matching l7 allow"
}

func mcpOrHTTPMethodMatch(protocol, pat, method string) bool {
	if strings.EqualFold(strings.TrimSpace(protocol), ProtocolJSONRPC) {
		return pat == "*" || pat == method
	}
	if strings.EqualFold(strings.TrimSpace(protocol), ProtocolMCP) {
		pat = strings.TrimSpace(pat)
		method = strings.TrimSpace(method)
		if pat == "" || pat == "*" {
			return true
		}
		return pat == method
	}
	return methodMatches(pat, method)
}

func methodMatches(pat, method string) bool {
	pat = strings.ToUpper(strings.TrimSpace(pat))
	if pat == "" || pat == "*" {
		return true
	}
	return pat == method
}
