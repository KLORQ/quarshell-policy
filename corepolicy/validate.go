package policy

import (
	"fmt"
	"net"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/KLORQ/quarshell-policy/internal/hostpattern"
	"gopkg.in/yaml.v3"
)

// Validate performs fail-closed structural checks.
func (d Document) Validate() error {
	if d.Landlock != nil {
		c := strings.ToLower(strings.TrimSpace(d.Landlock.Compatibility))
		if c == "" {
			c = "best_effort"
		}
		switch c {
		case "best_effort", "hard_requirement":
		default:
			return fmt.Errorf("policy: landlock.compatibility must be best_effort|hard_requirement")
		}
	}
	if d.FilesystemPolicy != nil {
		paths := append(append([]string{}, d.FilesystemPolicy.ReadOnly...), d.FilesystemPolicy.ReadWrite...)
		if len(paths) > 256 {
			return fmt.Errorf("policy: too many filesystem paths (%d)", len(paths))
		}
		for _, p := range paths {
			if err := validateFSPath(p); err != nil {
				return err
			}
		}
		if slices.Contains(d.FilesystemPolicy.ReadWrite, "/") {
			return fmt.Errorf("policy: filesystem_policy.read_write must not include '/'")
		}
	}
	if d.Process != nil {
		if err := validateProcessIdentity("run_as_user", d.Process.RunAsUser); err != nil {
			return err
		}
		if err := validateProcessIdentity("run_as_group", d.Process.RunAsGroup); err != nil {
			return err
		}
	}
	for key, rule := range d.NetworkPolicies {
		name := rule.Name
		if name == "" {
			name = key
		}
		bins := binaryPaths(rule.Binaries)
		for j, ep := range rule.Endpoints {
			r := ep
			if r.ID == "" {
				r.ID = name
			}
			if len(r.Binaries) == 0 && len(bins) > 0 {
				r.Binaries = bins
			}
			prefix := fmt.Sprintf("network_policies[%q].endpoints[%d]", key, j)
			if err := validateAllowRule(prefix, r); err != nil {
				return err
			}
		}
		for j, bin := range rule.Binaries {
			if !path.IsAbs(bin.Path) || hasDotSegment(bin.Path) {
				return fmt.Errorf("policy: network_policies[%q].binaries[%d]: absolute path without dot segments required", key, j)
			}
		}
	}
	if d.Inference != nil {
		if _, err := ExpandInferenceRules(d.Inference); err != nil {
			return err
		}
		for i, rule := range d.Inference.Allow {
			if rule.CredentialBinding != nil {
				return fmt.Errorf("policy: inference.allow[%d]: credential_binding is only valid on network_policies endpoints", i)
			}
			if err := validateAllowRule(fmt.Sprintf("inference.allow[%d]", i), rule); err != nil {
				return err
			}
		}
	}
	if d.Display != nil {
		mode := strings.ToLower(strings.TrimSpace(d.Display.Mode))
		if mode == "" {
			mode = "none"
		}
		switch mode {
		case "none", "novnc":
		default:
			return fmt.Errorf("policy: display.mode must be none|novnc")
		}
	}
	for i, b := range d.Binaries {
		b = strings.TrimSpace(b)
		if b == "" {
			return fmt.Errorf("policy: binaries[%d]: empty", i)
		}
		if !path.IsAbs(b) || hasDotSegment(b) {
			return fmt.Errorf("policy: binaries[%d]: must be absolute without dot segments", i)
		}
	}
	if err := validateNetworkMiddlewares(d.NetworkMiddlewares, d.NetworkPolicies); err != nil {
		return err
	}
	return nil
}

func validateNetworkMiddlewares(middlewares map[string]yaml.Node, networkPolicies map[string]NetworkPolicy) error {
	const maxConfigs = 10
	const maxSelectorPatterns = 32
	if len(middlewares) > maxConfigs {
		return fmt.Errorf("policy: network_middlewares has %d entries; maximum is %d", len(middlewares), maxConfigs)
	}
	type endpointSelector struct {
		Include []string `yaml:"include"`
		Exclude []string `yaml:"exclude"`
	}
	type middlewareConfig struct {
		Middleware string            `yaml:"middleware"`
		Order      int32             `yaml:"order"`
		OnError    string            `yaml:"on_error"`
		Endpoints  *endpointSelector `yaml:"endpoints"`
	}
	orders := make(map[int32]string, len(middlewares))
	for name, node := range middlewares {
		prefix := fmt.Sprintf("policy: network_middlewares[%q]", name)
		if name == "" {
			return fmt.Errorf("%s: name must not be empty", prefix)
		}
		var config middlewareConfig
		if err := node.Decode(&config); err != nil {
			return fmt.Errorf("%s: %w", prefix, err)
		}
		if config.Middleware == "" {
			return fmt.Errorf("%s.middleware must not be empty", prefix)
		}
		if previous, exists := orders[config.Order]; exists {
			return fmt.Errorf("policy: network_middlewares %q and %q share order %d", previous, name, config.Order)
		}
		orders[config.Order] = name
		if config.OnError != "" && config.OnError != "fail_closed" && config.OnError != "fail_open" {
			return fmt.Errorf("%s.on_error must be fail_closed|fail_open", prefix)
		}
		if config.Endpoints == nil {
			return fmt.Errorf("%s.endpoints is required", prefix)
		}
		if len(config.Endpoints.Include) == 0 {
			return fmt.Errorf("%s.endpoints.include must contain at least one host pattern", prefix)
		}
		patternCount := len(config.Endpoints.Include) + len(config.Endpoints.Exclude)
		if patternCount > maxSelectorPatterns {
			return fmt.Errorf("%s.endpoints has %d patterns; maximum is %d", prefix, patternCount, maxSelectorPatterns)
		}
		includes := make([]hostpattern.Pattern, 0, len(config.Endpoints.Include))
		excludes := make([]hostpattern.Pattern, 0, len(config.Endpoints.Exclude))
		for _, pattern := range config.Endpoints.Include {
			compiled, err := hostpattern.Parse(pattern)
			if err != nil {
				return fmt.Errorf("%s.endpoints has invalid host pattern %q: %w", prefix, pattern, err)
			}
			includes = append(includes, compiled)
		}
		for _, pattern := range config.Endpoints.Exclude {
			compiled, err := hostpattern.Parse(pattern)
			if err != nil {
				return fmt.Errorf("%s.endpoints has invalid host pattern %q: %w", prefix, pattern, err)
			}
			excludes = append(excludes, compiled)
		}
		if config.OnError == "" || config.OnError == "fail_closed" {
			for policyKey, networkPolicy := range networkPolicies {
				policyName := networkPolicy.Name
				if policyName == "" {
					policyName = policyKey
				}
				for _, endpoint := range networkPolicy.Endpoints {
					if endpoint.TLS != "skip" {
						continue
					}
					candidate, err := hostpattern.Parse(endpoint.Host)
					if err == nil && hostpattern.SelectorMayMatchPattern(includes, excludes, candidate) {
						return fmt.Errorf("policy: middleware %q may inspect endpoint %q in network policy %q with tls: skip", name, endpoint.Host, policyName)
					}
				}
			}
		}
	}
	return nil
}

func binaryPaths(bins []NetworkBinary) []string {
	var out []string
	for _, b := range bins {
		if p := strings.TrimSpace(b.Path); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// EffectivePorts returns ports, falling back to single Port.

// Enforcement modes.
const (
	EnforcementEnforce = "enforce"
	EnforcementAudit   = "audit"
)

// IsAudit reports whether L7 violations should be logged and allowed.

// IsAudit reports whether L7 violations should be logged and allowed.
func (r AllowRule) IsAudit() bool {
	return strings.EqualFold(strings.TrimSpace(r.Enforcement), EnforcementAudit)
}

// ValidateAllowRule validates one network allow entry (exported for provider profiles).

// ValidateAllowRule validates one network allow entry (exported for provider profiles).
func ValidateAllowRule(prefix string, rule AllowRule) error {
	return validateAllowRule(prefix, rule)
}

func validateAllowRule(prefix string, rule AllowRule) error {
	if strings.TrimSpace(rule.Host) == "" && len(rule.AllowedIPs) == 0 {
		return fmt.Errorf("policy: %s: host or allowed_ips required", prefix)
	}
	if binding := rule.CredentialBinding; binding != nil {
		if strings.TrimSpace(rule.Host) == "" {
			return fmt.Errorf("policy: %s: credential-bound endpoint must define a host", prefix)
		}
		provider := strings.TrimSpace(binding.Provider)
		if provider == "" {
			return fmt.Errorf("policy: %s.credential_binding.provider required", prefix)
		}
		if provider != binding.Provider {
			return fmt.Errorf("policy: %s.credential_binding.provider must not contain leading or trailing whitespace", prefix)
		}
	}
	if rule.RequestBodyCredentialRewrite && strings.ToLower(strings.TrimSpace(rule.Protocol)) != ProtocolREST {
		return fmt.Errorf("policy: %s: request_body_credential_rewrite requires protocol: rest", prefix)
	}
	if rule.RequestBodyCredentialRewrite && strings.TrimSpace(rule.CredentialSigning) != "" {
		return fmt.Errorf("policy: %s: credential_signing and request_body_credential_rewrite are mutually exclusive", prefix)
	}
	ports := rule.EffectivePorts()
	if len(ports) == 0 {
		return fmt.Errorf("policy: %s: port or ports required", prefix)
	}
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("policy: %s: invalid port %d", prefix, p)
		}
	}
	if rule.Host != "" && isTLDWildcard(rule.Host) {
		return fmt.Errorf("policy: %s: TLD wildcard host %q rejected", prefix, rule.Host)
	}
	enf := strings.ToLower(strings.TrimSpace(rule.Enforcement))
	switch enf {
	case "", EnforcementEnforce, EnforcementAudit:
	default:
		return fmt.Errorf("policy: %s: enforcement must be enforce|audit (got %q)", prefix, rule.Enforcement)
	}
	for j, cidr := range rule.AllowedIPs {
		if err := validateCIDROrIP(fmt.Sprintf("%s.allowed_ips[%d]", prefix, j), cidr); err != nil {
			return err
		}
	}
	return validateL7(prefix, rule)
}

func validateL7(prefix string, rule AllowRule) error {
	proto := strings.ToLower(strings.TrimSpace(rule.Protocol))
	access := strings.ToLower(strings.TrimSpace(rule.Access))
	if rule.Rules != nil && len(rule.Rules) == 0 {
		return fmt.Errorf("policy: %s.rules must not be empty", prefix)
	}
	if rule.DenyRules != nil && len(rule.DenyRules) == 0 {
		return fmt.Errorf("policy: %s.deny_rules must not be empty", prefix)
	}

	switch proto {
	case "", ProtocolREST, ProtocolWebsocket, ProtocolGraphQL, ProtocolSQL, ProtocolTCP, ProtocolMCP, ProtocolJSONRPC:
	default:
		return fmt.Errorf("policy: %s: protocol must be tcp|rest|websocket|graphql|sql|json-rpc|mcp (got %q)", prefix, rule.Protocol)
	}
	if rule.MCP != nil && proto != ProtocolMCP {
		return fmt.Errorf("policy: %s: mcp options require protocol: mcp", prefix)
	}
	if rule.JSONRPC != nil && rule.JSONRPC.MaxBodyBytes != nil && *rule.JSONRPC.MaxBodyBytes == 0 {
		return fmt.Errorf("policy: %s.json_rpc.max_body_bytes must be a positive integer", prefix)
	}
	if rule.GraphQLMaxBodyBytes != nil && *rule.GraphQLMaxBodyBytes == 0 {
		return fmt.Errorf("policy: %s.graphql_max_body_bytes must be a positive integer", prefix)
	}
	if mode := rule.PersistedQueries; mode != "" && mode != "deny" && mode != "allow_registered" {
		return fmt.Errorf("policy: %s.persisted_queries must be deny|allow_registered", prefix)
	}
	for id, operation := range rule.GraphQLPersistedQueries {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("policy: %s.graphql_persisted_queries contains an empty id", prefix)
		}
		if operation.OperationType != "query" && operation.OperationType != "mutation" && operation.OperationType != "subscription" {
			return fmt.Errorf("policy: %s.graphql_persisted_queries[%q].operation_type must be query|mutation|subscription", prefix, id)
		}
		if err := validateGraphQLFields(fmt.Sprintf("%s.graphql_persisted_queries[%q].fields", prefix, id), operation.Fields); err != nil {
			return err
		}
	}
	if rule.MCP != nil {
		if rule.MCP.Versions != nil && len(rule.MCP.Versions) == 0 {
			return fmt.Errorf("policy: %s.mcp.versions: must not be empty when specified", prefix)
		}
		seenVersions := make(map[string]struct{}, len(rule.MCP.Versions))
		for i, version := range rule.MCP.Versions {
			if version != "2025-03-26" && version != "2025-06-18" && version != "2025-11-25" {
				return fmt.Errorf("policy: %s.mcp.versions[%d]: unsupported MCP version %q", prefix, i, version)
			}
			if _, exists := seenVersions[version]; exists {
				return fmt.Errorf("policy: %s.mcp.versions[%d]: duplicate MCP version %q", prefix, i, version)
			}
			seenVersions[version] = struct{}{}
		}
	}
	// OpenShell treats only "skip" specially. "terminate" and "passthrough"
	// are deprecated aliases for automatic TLS handling; other string values
	// also follow the pinned parser's Auto fallback.
	switch access {
	case "", AccessReadOnly, AccessReadWrite, AccessFull:
	default:
		return fmt.Errorf("policy: %s: access must be read-only|read-write|full (got %q)", prefix, rule.Access)
	}
	if access != "" && len(rule.Rules) > 0 {
		return fmt.Errorf("policy: %s: access and rules are mutually exclusive", prefix)
	}
	if rule.HasL7Policy() {
		switch proto {
		case ProtocolREST, ProtocolWebsocket, ProtocolGraphQL, ProtocolSQL, ProtocolMCP, ProtocolJSONRPC:
		case "":
			return fmt.Errorf("policy: %s: L7 fields require protocol", prefix)
		default:
			return fmt.Errorf("policy: %s: protocol %q unsupported", prefix, proto)
		}
		if proto == ProtocolTCP {
			return fmt.Errorf("policy: %s: protocol tcp does not support access, rules, or deny_rules; remove those L7 fields", prefix)
		}
		if proto == ProtocolSQL && !rule.IsAudit() {
			return fmt.Errorf("policy: %s: SQL enforcement requires full SQL parsing (not available in v1). Use enforcement: audit", prefix)
		}
		if proto == ProtocolSQL {
			for i, item := range rule.Rules {
				if item.Allow == nil || strings.TrimSpace(item.Allow.Command) == "" {
					return fmt.Errorf("policy: %s.rules[%d].allow.command required for sql", prefix, i)
				}
			}
			for i, item := range rule.DenyRules {
				if strings.TrimSpace(item.Command) == "" {
					return fmt.Errorf("policy: %s.deny_rules[%d].command required for sql", prefix, i)
				}
			}
		}
		allowAllMCPMethods := proto == ProtocolMCP && rule.MCP != nil && rule.MCP.AllowAllKnownMCPMethods != nil && *rule.MCP.AllowAllKnownMCPMethods
		methodProtocol := proto == ProtocolMCP || proto == ProtocolJSONRPC
		if access == "" && len(rule.Rules) == 0 && len(rule.DenyRules) == 0 && !allowAllMCPMethods {
			return fmt.Errorf("policy: %s: protocol %q requires access or rules", prefix, proto)
		}
		if access != "" {
			if methodProtocol {
				return fmt.Errorf("policy: %s: access presets are not supported for %s; specify method rules", prefix, proto)
			}
			if rule.ExpandedL7Allows() == nil {
				return fmt.Errorf("policy: %s: invalid access %q", prefix, rule.Access)
			}
		}
		strictToolNames := rule.MCP == nil || rule.MCP.StrictToolNames == nil || *rule.MCP.StrictToolNames
		for i, deny := range rule.DenyRules {
			if err := validateQuerySelectors(deny.Query, proto); err != nil {
				return fmt.Errorf("policy: %s.deny_rules[%d]: %w", prefix, i, err)
			}
			if err := validateToolSelector(deny.Tool, deny.Params, proto, deny.Method, strictToolNames); err != nil {
				return fmt.Errorf("policy: %s.deny_rules[%d]: %w", prefix, i, err)
			}
		}
		if proto == ProtocolSQL {
			for i, item := range rule.Rules {
				a := item.Allow
				if a != nil && (a.Method != "" || a.Path != "" || len(a.Query) > 0 || a.Tool != nil || len(a.Params) > 0 || a.OperationType != "" || a.OperationName != "" || len(a.Fields) > 0) {
					return fmt.Errorf("policy: %s.rules[%d]: SQL rules support command only", prefix, i)
				}
			}
			for i, item := range rule.DenyRules {
				if item.Method != "" || item.Path != "" || len(item.Query) > 0 || item.Tool != nil || len(item.Params) > 0 || item.OperationType != "" || item.OperationName != "" || len(item.Fields) > 0 {
					return fmt.Errorf("policy: %s.deny_rules[%d]: SQL rules support command only", prefix, i)
				}
			}
		}
		for i, r := range rule.Rules {
			if r.Allow == nil {
				return fmt.Errorf("policy: %s.rules[%d]: allow required", prefix, i)
			}
			if err := validateQuerySelectors(r.Allow.Query, proto); err != nil {
				return fmt.Errorf("policy: %s.rules[%d]: %w", prefix, i, err)
			}
			if err := validateToolSelector(r.Allow.Tool, r.Allow.Params, proto, r.Allow.Method, strictToolNames); err != nil {
				return fmt.Errorf("policy: %s.rules[%d]: %w", prefix, i, err)
			}
			if methodProtocol && strings.TrimSpace(r.Allow.Method) == "" && !allowAllMCPMethods {
				return fmt.Errorf("policy: %s.rules[%d].allow.method required for %s", prefix, i, proto)
			}
			if proto == ProtocolJSONRPC {
				method := strings.TrimSpace(r.Allow.Method)
				if method != "*" && strings.ContainsAny(method, "*?[]") {
					return fmt.Errorf("policy: %s.rules[%d].allow.method: JSON-RPC supports exact methods or *", prefix, i)
				}
				if r.Allow.Tool != nil {
					return fmt.Errorf("policy: %s.rules[%d].allow.tool is only valid for MCP", prefix, i)
				}
			}
			if proto == ProtocolGraphQL || (proto == ProtocolWebsocket && hasGraphQLSelectors(r.Allow.OperationType, r.Allow.OperationName, r.Allow.Fields)) {
				if err := validateGraphQLRule(fmt.Sprintf("%s.rules[%d].allow", prefix, i), r.Allow.OperationType, r.Allow.Fields); err != nil {
					return err
				}
				if r.Allow.Tool != nil {
					return fmt.Errorf("policy: %s.rules[%d].allow.tool is only valid for MCP", prefix, i)
				}
			}
		}
		if proto == ProtocolJSONRPC {
			for i, deny := range rule.DenyRules {
				method := strings.TrimSpace(deny.Method)
				if method == "" {
					return fmt.Errorf("policy: %s.deny_rules[%d].method required for json-rpc", prefix, i)
				}
				if method != "*" && strings.ContainsAny(method, "*?[]") {
					return fmt.Errorf("policy: %s.deny_rules[%d].method: JSON-RPC supports exact methods or *", prefix, i)
				}
				if deny.Tool != nil {
					return fmt.Errorf("policy: %s.deny_rules[%d].tool is only valid for MCP", prefix, i)
				}
			}
		}
		if proto == ProtocolGraphQL || proto == ProtocolWebsocket {
			for i, deny := range rule.DenyRules {
				if proto == ProtocolGraphQL || hasGraphQLSelectors(deny.OperationType, deny.OperationName, deny.Fields) {
					if err := validateGraphQLRule(fmt.Sprintf("%s.deny_rules[%d]", prefix, i), deny.OperationType, deny.Fields); err != nil {
						return err
					}
					if deny.Tool != nil {
						return fmt.Errorf("policy: %s.deny_rules[%d].tool is only valid for MCP", prefix, i)
					}
				}
			}
		}
		// TLS is auto-detected for L7 endpoints by OpenShell. Explicit skip is
		// accepted as an opt-out even though encrypted L7 rules cannot run then.
	}
	return nil
}

func hasGraphQLSelectors(operationType, operationName string, fields []string) bool {
	return operationType != "" || operationName != "" || len(fields) > 0
}

func validateGraphQLRule(prefix, operationType string, fields []string) error {
	if operationType == "" {
		return fmt.Errorf("policy: %s.operation_type required for GraphQL rules", prefix)
	}
	switch strings.ToLower(operationType) {
	case "query", "mutation", "subscription", "*":
	default:
		return fmt.Errorf("policy: %s.operation_type must be query|mutation|subscription|*", prefix)
	}
	return validateGraphQLFields(prefix+".fields", fields)
}

func validateGraphQLFields(prefix string, fields []string) error {
	if fields != nil && len(fields) == 0 {
		return fmt.Errorf("policy: %s must not be empty when specified", prefix)
	}
	for i, field := range fields {
		if strings.TrimSpace(field) == "" {
			return fmt.Errorf("policy: %s[%d] must not be empty", prefix, i)
		}
	}
	return nil
}

func validateCIDROrIP(prefix, s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("policy: %s: empty", prefix)
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return nil
	}
	if ip := net.ParseIP(s); ip != nil {
		return nil
	}
	return fmt.Errorf("policy: %s: invalid IP/CIDR %q", prefix, s)
}

func validateFSPath(p string) error {
	if p == "" {
		return fmt.Errorf("policy: empty filesystem path")
	}
	if len(p) > 4096 {
		return fmt.Errorf("policy: filesystem path too long (%d)", len(p))
	}
	if !path.IsAbs(p) {
		return fmt.Errorf("policy: filesystem path must be absolute: %q", p)
	}
	if hasDotSegment(p) {
		return fmt.Errorf("policy: filesystem path must not contain dot segments: %q", p)
	}
	return nil
}

func hasDotSegment(p string) bool {
	for segment := range strings.SplitSeq(p, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

func validateProcessIdentity(field, value string) error {
	if value == "" {
		return nil
	}
	if value == "sandbox" {
		return nil
	}
	n, err := strconv.ParseUint(value, 10, 32)
	if err == nil && n > 0 && n < (1<<32)-1 {
		return nil
	}
	return fmt.Errorf("policy: process.%s must be 'sandbox' or a numeric UID/GID in range [1, 4294967294], got %q", field, value)
}

func isTLDWildcard(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "*" || h == "**" {
		return true
	}
	if strings.HasPrefix(h, "*.") && !strings.Contains(h[2:], ".") {
		return true
	}
	if strings.HasPrefix(h, "**.") && !strings.Contains(h[3:], ".") {
		return true
	}
	return false
}
