package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/KLORQ/quarshell-core/domain"
)

// ProviderRulePrefix marks network rules composed from provider profiles.
// Authored rules must not use this prefix; the gateway strips such rules
// before publishing a provider-derived effective policy.
const ProviderRulePrefix = "_provider_"

// ProviderPolicyLayer is one provider-authored network rule layer.
type ProviderPolicyLayer struct {
	RuleName string
	Rule     NetworkPolicyRule
}

// IsProviderRuleName reports whether a rule key belongs to a provider layer.
func IsProviderRuleName(name string) bool {
	return strings.HasPrefix(name, ProviderRulePrefix)
}

// ProviderRuleName derives the reserved rule key for a provider name.
func ProviderRuleName(provider string) string {
	var builder strings.Builder
	for _, char := range provider {
		switch {
		case char >= 'a' && char <= 'z', char >= '0' && char <= '9', char == '_':
			builder.WriteRune(char)
		case char >= 'A' && char <= 'Z':
			builder.WriteRune(char - 'A' + 'a')
		default:
			builder.WriteByte('_')
		}
	}
	sanitized := strings.Trim(builder.String(), "_")
	if sanitized == "" {
		return ProviderRulePrefix + "unnamed"
	}
	return ProviderRulePrefix + sanitized
}

// StripProviderRuleNames removes provider-composed rules in place and reports
// whether the policy changed.
func StripProviderRuleNames(policy *Policy) bool {
	if policy == nil || !policy.NetworkPolicies.HasValue() {
		return false
	}
	changed := false
	for name := range policy.NetworkPolicies.Value {
		if IsProviderRuleName(name) {
			delete(policy.NetworkPolicies.Value, name)
			changed = true
		}
	}
	return changed
}

// ComposeEffectivePolicy returns derived policy data: a deep copy of the
// source policy with each provider layer inserted under a reserved key.
// User-authored rules are never overwritten; colliding provider keys gain a
// numeric suffix. The source policy and the layers are not modified.
func ComposeEffectivePolicy(source *Policy, layers []ProviderPolicyLayer) *Policy {
	if source == nil {
		return nil
	}
	effective := clonePolicy(source)
	if !effective.NetworkPolicies.HasValue() {
		effective.NetworkPolicies = domain.Some(map[string]NetworkPolicyRule{})
	}
	for _, layer := range layers {
		key := uniqueProviderRuleKey(effective.NetworkPolicies.Value, layer.RuleName)
		rule := cloneNetworkPolicyRule(layer.Rule)
		if !rule.Name.HasValue() || rule.Name.Value == "" {
			rule.Name = domain.Some(key)
		}
		effective.NetworkPolicies.Value[key] = rule
	}
	return effective
}

// EffectiveSource names the authored policy that produced derived data.
type EffectiveSource string

const (
	// SourceNone means no authored policy was supplied.
	SourceNone EffectiveSource = ""
	// SourceSandbox means the sandbox policy is authoritative.
	SourceSandbox EffectiveSource = "sandbox"
	// SourceGlobal means the gateway-global policy is authoritative.
	SourceGlobal EffectiveSource = "global"
)

// ComposeLayers resolves the effective authored policy and then appends
// provider layers. A global policy is the complete effective policy: when it
// exists it replaces the sandbox policy, matching the pinned upstream gateway.
// Provider layers are always derived data on top of that choice.
func ComposeLayers(global, sandbox *Policy, layers []ProviderPolicyLayer) (*Policy, EffectiveSource, error) {
	base := sandbox
	source := SourceSandbox
	if global != nil {
		base = global
		source = SourceGlobal
	}
	if base == nil {
		return nil, SourceNone, domain.Invalidf("policy.compose", "no authored policy layer")
	}
	return ComposeEffectivePolicy(base, layers), source, nil
}

// DerivedHash returns a stable digest of the derived policy. It is not the
// authored source hash; it exists so composed policies can be fenced and
// compared without re-parsing the source document.
func (p *Policy) DerivedHash() (string, error) {
	if p == nil {
		return "", domain.Invalidf("policy.hash", "nil policy")
	}
	encoded, err := json.Marshal(p)
	if err != nil {
		return "", domain.Wrap(err, "policy.hash", "encode derived policy")
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// Compose returns the same derived policy as ComposeEffectivePolicy.
func (p *Policy) Compose(layers []ProviderPolicyLayer) *Policy {
	return ComposeEffectivePolicy(p, layers)
}

func uniqueProviderRuleKey(rules map[string]NetworkPolicyRule, preferred string) string {
	if _, exists := rules[preferred]; !exists {
		return preferred
	}
	for suffix := uint64(2); ; suffix++ {
		candidate := preferred + "_" + strconv.FormatUint(suffix, 10)
		if _, exists := rules[candidate]; !exists {
			return candidate
		}
	}
}

func clonePolicy(source *Policy) *Policy {
	clone := &Policy{Version: source.Version}
	clone.Filesystem = source.Filesystem
	if source.Filesystem.HasValue() {
		clone.Filesystem.Value.ReadOnly = append([]string(nil), source.Filesystem.Value.ReadOnly...)
		clone.Filesystem.Value.ReadWrite = append([]string(nil), source.Filesystem.Value.ReadWrite...)
	}
	clone.Landlock = source.Landlock
	clone.Process = source.Process
	if source.NetworkPolicies.HasValue() {
		rules := make(map[string]NetworkPolicyRule, len(source.NetworkPolicies.Value))
		for name, rule := range source.NetworkPolicies.Value {
			rules[name] = cloneNetworkPolicyRule(rule)
		}
		clone.NetworkPolicies = domain.Some(rules)
	}
	if source.NetworkMiddlewares.HasValue() {
		middlewares := make(map[string]NetworkMiddleware, len(source.NetworkMiddlewares.Value))
		for name, middleware := range source.NetworkMiddlewares.Value {
			middlewares[name] = cloneMiddleware(middleware)
		}
		clone.NetworkMiddlewares = domain.Some(middlewares)
	}
	return clone
}

func cloneNetworkPolicyRule(rule NetworkPolicyRule) NetworkPolicyRule {
	clone := rule
	clone.Endpoints = make([]NetworkEndpoint, len(rule.Endpoints))
	for index, endpoint := range rule.Endpoints {
		clone.Endpoints[index] = cloneEndpoint(endpoint)
	}
	clone.Binaries = make([]NetworkBinary, len(rule.Binaries))
	copy(clone.Binaries, rule.Binaries)
	return clone
}

func cloneEndpoint(endpoint NetworkEndpoint) NetworkEndpoint {
	clone := endpoint
	clone.Ports = append([]uint16(nil), endpoint.Ports...)
	clone.AllowedIPs = append([]string(nil), endpoint.AllowedIPs...)
	clone.Rules = make([]L7Rule, len(endpoint.Rules))
	for index, rule := range endpoint.Rules {
		clone.Rules[index] = cloneAllowRule(rule)
	}
	clone.DenyRules = make([]L7DenyRule, len(endpoint.DenyRules))
	for index, rule := range endpoint.DenyRules {
		clone.DenyRules[index] = cloneDenyRule(rule)
	}
	if endpoint.GraphqlPersistedQueries.HasValue() {
		queries := make(map[string]GraphqlOperation, len(endpoint.GraphqlPersistedQueries.Value))
		for name, operation := range endpoint.GraphqlPersistedQueries.Value {
			operation.Fields = append([]string(nil), operation.Fields...)
			queries[name] = operation
		}
		clone.GraphqlPersistedQueries = domain.Some(queries)
	}
	if endpoint.MCP.HasValue() && endpoint.MCP.Value.Versions.HasValue() {
		versions := append([]string(nil), endpoint.MCP.Value.Versions.Value...)
		clone.MCP.Value.Versions = domain.Some(versions)
	}
	return clone
}

func cloneDenyRule(rule L7DenyRule) L7DenyRule {
	clone := rule
	clone.Fields = append([]string(nil), rule.Fields...)
	return clone
}

func cloneAllowRule(rule L7Rule) L7Rule {
	clone := rule
	clone.Allow.Fields = append([]string(nil), rule.Allow.Fields...)
	return clone
}

func cloneMiddleware(middleware NetworkMiddleware) NetworkMiddleware {
	clone := middleware
	if middleware.Endpoints.HasValue() {
		clone.Endpoints.Value.Include = append([]string(nil), middleware.Endpoints.Value.Include...)
		clone.Endpoints.Value.Exclude = append([]string(nil), middleware.Endpoints.Value.Exclude...)
	}
	return clone
}
