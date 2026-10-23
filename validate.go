package policy

import (
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/KLORQ/quarshell-core/domain"
)

// Validate applies the pinned runtime policy validation rules. It is stronger
// than Typed: Typed proves the document can be represented, Validate proves the
// represented policy is safe to activate.
func (p *Policy) Validate() error {
	if p == nil {
		return domain.Invalidf("policy.validate", "nil policy")
	}
	var violations []string
	violations = append(violations, p.validateProcess()...)
	violations = append(violations, p.validateLandlock()...)
	violations = append(violations, p.validateFilesystem()...)
	violations = append(violations, p.validateMiddlewares()...)
	if p.NetworkPolicies.HasValue() {
		names := make([]string, 0, len(p.NetworkPolicies.Value))
		for name := range p.NetworkPolicies.Value {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			rule := p.NetworkPolicies.Value[name]
			effectiveName := name
			if rule.Name.HasValue() && rule.Name.Value != "" {
				effectiveName = rule.Name.Value
			}
			for index, endpoint := range rule.Endpoints {
				for _, reason := range validateEndpoint(effectiveName, endpoint) {
					violations = append(violations, "network policy '"+effectiveName+"' endpoint "+strconv.Itoa(index)+": "+reason)
				}
			}
		}
	}
	if len(violations) > 0 {
		return domain.Invalidf("policy.validate", "%s", strings.Join(violations, "; "))
	}
	return nil
}

const (
	maxMiddlewareConfigs          = 10
	maxMiddlewareSelectorPatterns = 32
)

func (p *Policy) validateMiddlewares() []string {
	if !p.NetworkMiddlewares.HasValue() {
		return nil
	}
	var violations []string
	if len(p.NetworkMiddlewares.Value) > maxMiddlewareConfigs {
		violations = append(violations, "too many middleware configurations")
	}
	names := make([]string, 0, len(p.NetworkMiddlewares.Value))
	for name := range p.NetworkMiddlewares.Value {
		names = append(names, name)
	}
	sort.Strings(names)
	orders := map[int32]string{}
	for _, name := range names {
		middleware := p.NetworkMiddlewares.Value[name]
		if name == "" {
			violations = append(violations, "middleware name must not be empty")
		}
		if first, exists := orders[middleware.Order]; exists {
			violations = append(violations, "middleware '"+name+"' duplicates order used by '"+first+"'")
		} else {
			orders[middleware.Order] = name
		}
		switch middleware.OnError {
		case "", "fail_closed", "fail_open":
		default:
			violations = append(violations, "middleware '"+name+"' has invalid on_error")
		}
		if !middleware.Endpoints.HasValue() {
			violations = append(violations, "middleware '"+name+"' endpoint selector is required")
			continue
		}
		selector := middleware.Endpoints.Value
		if len(selector.Include) == 0 {
			violations = append(violations, "middleware '"+name+"' selector must include at least one host pattern")
		}
		if len(selector.Include)+len(selector.Exclude) > maxMiddlewareSelectorPatterns {
			violations = append(violations, "middleware '"+name+"' has too many selector patterns")
			continue
		}
		for _, pattern := range append(append([]string{}, selector.Include...), selector.Exclude...) {
			if err := validateHostPattern(pattern); err != nil {
				violations = append(violations, "middleware '"+name+"' selector pattern is invalid: "+err.Error())
			}
		}
		if middleware.OnError == "" || middleware.OnError == "fail_closed" {
			for policyName, rule := range p.NetworkPolicies.Value {
				for _, endpoint := range rule.Endpoints {
					if endpoint.TLS == "skip" && selectorMatchesHost(selector, endpoint.Host) {
						violations = append(violations, "middleware '"+name+"' conflicts with tls skip on policy '"+policyName+"'")
					}
				}
			}
		}
	}
	return violations
}

func validateHostPattern(pattern string) error {
	if pattern == "" {
		return domain.Invalidf("policy.validate", "host pattern must not be empty")
	}
	if strings.ContainsAny(pattern, " \t\r\n{}") || strings.Contains(pattern, "***") {
		return domain.Invalidf("policy.validate", "host pattern is invalid")
	}
	return nil
}

func selectorMatchesHost(selector MiddlewareEndpointSelector, host string) bool {
	matched := false
	for _, pattern := range selector.Include {
		if globMatch(pattern, host, '.') {
			matched = true
			break
		}
	}
	if !matched {
		return false
	}
	for _, pattern := range selector.Exclude {
		if globMatch(pattern, host, '.') {
			return false
		}
	}
	return true
}

func (p *Policy) validateProcess() []string {
	if !p.Process.HasValue() {
		return nil
	}
	var violations []string
	for field, value := range map[string]domain.Field[string]{
		"run_as_user":  p.Process.Value.RunAsUser,
		"run_as_group": p.Process.Value.RunAsGroup,
	} {
		if !value.HasValue() || value.Value == "" {
			continue
		}
		if !validSandboxIdentity(value.Value) {
			violations = append(violations, field+" must be 'sandbox' or a numeric UID/GID in [1, 4294967294]")
		}
	}
	return violations
}

func validSandboxIdentity(value string) bool {
	if value == "sandbox" {
		return true
	}
	number, err := strconv.ParseUint(value, 10, 32)
	return err == nil && number >= 1 && number <= 4294967294
}

func (p *Policy) validateLandlock() []string {
	if !p.Landlock.HasValue() {
		return nil
	}
	switch p.Landlock.Value.Compatibility.OrElse("") {
	case "", "best_effort", "hard_requirement":
		return nil
	default:
		return []string{"landlock.compatibility must be best_effort or hard_requirement"}
	}
}

func (p *Policy) validateFilesystem() []string {
	if !p.Filesystem.HasValue() {
		return nil
	}
	filesystem := p.Filesystem.Value
	var violations []string
	totalPaths := len(filesystem.ReadOnly) + len(filesystem.ReadWrite)
	if totalPaths > 256 {
		violations = append(violations, "too many filesystem paths")
	}
	for _, path := range append(append([]string{}, filesystem.ReadOnly...), filesystem.ReadWrite...) {
		if len(path) > 4096 {
			violations = append(violations, "filesystem path exceeds maximum length")
			continue
		}
		if !strings.HasPrefix(path, "/") {
			violations = append(violations, "filesystem path must be absolute")
			continue
		}
		for _, part := range strings.Split(path, "/") {
			if part == ".." {
				violations = append(violations, "filesystem path must not contain '..'")
				break
			}
		}
	}
	for _, path := range filesystem.ReadWrite {
		if strings.TrimRight(path, "/") == "" {
			violations = append(violations, "read_write must not grant the filesystem root")
		}
	}
	return violations
}

func validateEndpoint(policyName string, endpoint NetworkEndpoint) []string {
	_ = policyName
	var violations []string
	protocol := endpoint.Protocol
	l7 := knownL7Protocol(protocol)
	explicitTCP := strings.EqualFold(protocol, "tcp")
	jsonrpcFamily := l7 == "json-rpc" || l7 == "mcp"

	if endpoint.Host == "" && len(endpoint.AllowedIPs) == 0 {
		violations = append(violations, "endpoint has no host")
	}
	if explicitTCP {
		if _, err := netip.ParseAddr(endpoint.Host); err == nil {
			violations = append(violations, "protocol tcp requires a DNS hostname, not an IP literal")
		} else if strings.TrimSpace(endpoint.Host) != endpoint.Host || strings.HasSuffix(endpoint.Host, ".") {
			violations = append(violations, "protocol tcp host must not have whitespace or a trailing DNS root dot")
		} else if !validDNSHost(strings.NewReplacer("**", "x", "*", "x").Replace(endpoint.Host)) {
			violations = append(violations, "protocol tcp host cannot represent a valid DNS name")
		}
	}
	if strings.Contains(endpoint.Host, "*") && (strings.HasPrefix(endpoint.Host, "*.") || strings.HasPrefix(endpoint.Host, "**.")) {
		if strings.Count(endpoint.Host, ".") <= 1 {
			violations = append(violations, "endpoint host uses a TLD wildcard")
		}
	}
	if hostWildcardShapeInvalid(endpoint.Host) {
		violations = append(violations, "endpoint host has an invalid wildcard shape")
	}

	effectivePorts := endpoint.Ports
	if len(effectivePorts) == 0 && endpoint.Port.HasValue() && endpoint.Port.Value != 0 {
		effectivePorts = []uint16{endpoint.Port.Value}
	}
	if len(effectivePorts) == 0 {
		violations = append(violations, "endpoint has no effective port")
	}
	for _, port := range effectivePorts {
		if port == 0 {
			violations = append(violations, "endpoint port must be between 1 and 65535")
		}
	}

	if protocol != "" && l7 == "" && !explicitTCP {
		violations = append(violations, "unknown protocol '"+protocol+"' (expected tcp, rest, websocket, graphql, sql, json-rpc, or mcp)")
	}
	if explicitTCP && (endpoint.Access != "" || len(endpoint.Rules) > 0 || len(endpoint.DenyRules) > 0) {
		violations = append(violations, "protocol tcp does not support access, rules, or deny_rules")
	}
	if len(endpoint.Rules) > 0 && endpoint.Access != "" {
		violations = append(violations, "rules and access are mutually exclusive")
	}
	if jsonrpcFamily && endpoint.Access != "" {
		violations = append(violations, "protocol "+protocol+" does not support access presets")
	}
	if l7 == "json-rpc" && len(endpoint.Rules) == 0 && endpoint.Access == "" {
		violations = append(violations, "protocol json-rpc requires explicit rules with allow.method")
	}
	if l7 != "" && l7 != "mcp" && l7 != "json-rpc" && len(endpoint.Rules) == 0 && endpoint.Access == "" {
		violations = append(violations, "protocol requires rules or access to define allowed traffic")
	}
	allowAll := endpoint.MCP.HasValue() && endpoint.MCP.Value.AllowAllKnownMCPMethods.HasValue() && endpoint.MCP.Value.AllowAllKnownMCPMethods.Value
	if l7 == "mcp" && len(endpoint.Rules) == 0 && endpoint.Access == "" && !allowAll {
		violations = append(violations, "protocol mcp requires rules when mcp.allow_all_known_mcp_methods is false")
	}
	if len(endpoint.Rules) > 0 && rulesWouldDenyAll(endpoint.Rules) && (l7 != "mcp" || !allowAll) {
		violations = append(violations, "rules would deny all traffic (no allow clause found)")
	}
	if len(endpoint.DenyRules) > 0 && l7 == "" {
		violations = append(violations, "deny_rules require protocol (L7 inspection must be enabled)")
	}
	if len(endpoint.DenyRules) > 0 && l7 != "mcp" && len(endpoint.Rules) == 0 && endpoint.Access == "" {
		violations = append(violations, "deny_rules require rules or access to define the base allow set")
	}
	if explicitTCP {
		if endpoint.Enforcement != "" || endpoint.Path != "" || endpoint.AllowEncodedSlash ||
			endpoint.WebsocketCredentialRewrite || endpoint.RequestBodyCredentialRewrite ||
			endpoint.PersistedQueries != "" || endpoint.GraphqlPersistedQueries.HasValue() ||
			endpoint.GraphqlMaxBodyBytes > 0 || endpoint.JSONRPC.HasValue() || endpoint.MCP.HasValue() {
			violations = append(violations, "protocol tcp does not support L7-only fields")
		}
	}
	if endpoint.Path != "" && !strings.HasPrefix(endpoint.Path, "/") && endpoint.Path != "**" {
		violations = append(violations, "path must start with '/' or be '**'")
	}
	if endpoint.PersistedQueries != "" && endpoint.PersistedQueries != "deny" && endpoint.PersistedQueries != "allow_registered" {
		violations = append(violations, "persisted_queries must be 'deny' or 'allow_registered'")
	}
	if strings.EqualFold(protocol, "sql") && endpoint.Enforcement == "enforce" {
		violations = append(violations, "SQL enforcement requires full SQL parsing; use enforcement: audit")
	}
	if strings.EqualFold(protocol, "graphql") {
		for ruleIndex, rule := range endpoint.Rules {
			if !validGraphqlOperation(rule.Allow.OperationType) {
				violations = append(violations, "rules["+strconv.Itoa(ruleIndex)+"].allow.operation_type must be query, mutation, or subscription")
			}
		}
		for ruleIndex, rule := range endpoint.DenyRules {
			if !validGraphqlOperation(rule.OperationType) {
				violations = append(violations, "deny_rules["+strconv.Itoa(ruleIndex)+"].operation_type must be query, mutation, or subscription")
			}
		}
		for key, operation := range endpoint.GraphqlPersistedQueries.Value {
			if !validGraphqlOperation(operation.OperationType) {
				violations = append(violations, "graphql_persisted_queries["+key+"].operation_type must be query, mutation, or subscription")
			}
		}
	}
	if endpoint.CredentialSigning != "" {
		switch endpoint.CredentialSigning {
		case "sigv4", "sigv4:body", "sigv4:no_body":
		default:
			violations = append(violations, "unknown credential_signing value")
		}
		if endpoint.SigningService == "" {
			violations = append(violations, "credential_signing requires signing_service")
		}
		if endpoint.RequestBodyCredentialRewrite {
			violations = append(violations, "credential_signing conflicts with request_body_credential_rewrite")
		}
	}
	return violations
}

func validDNSHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

func hostWildcardShapeInvalid(host string) bool {
	if host == "*" || host == "**" {
		return true
	}
	if !strings.Contains(host, "*") {
		return false
	}
	labels := strings.Split(host, ".")
	if labels[0] != "**" && strings.Contains(labels[0], "**") {
		return true
	}
	for _, label := range labels[1:] {
		if strings.Contains(label, "**") || (strings.Contains(label, "*") && label != "*") {
			return true
		}
	}
	return false
}

func knownL7Protocol(protocol string) string {
	switch strings.ToLower(protocol) {
	case "rest", "websocket", "graphql", "sql", "json-rpc", "mcp":
		return strings.ToLower(protocol)
	default:
		return ""
	}
}

func validGraphqlOperation(value string) bool {
	return value == "query" || value == "mutation" || value == "subscription"
}

func rulesWouldDenyAll(rules []L7Rule) bool {
	for _, rule := range rules {
		allow := rule.Allow
		if allow.Method != "" || allow.Path != "" || allow.Command != "" ||
			allow.OperationType != "" || allow.OperationName != "" || len(allow.Fields) > 0 ||
			len(allow.Query) > 0 || allow.Tool != nil || allow.Params != nil {
			return false
		}
	}
	return true
}
