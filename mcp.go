package policy

import (
	"sort"
	"strings"

	"github.com/KLORQ/quarshell-core/domain"
)

// DefaultMCPProtocolVersion is pinned when authored policy omits versions.
const DefaultMCPProtocolVersion = "2025-11-25"

var supportedMCPVersions = []string{
	"2025-03-26",
	"2025-06-18",
	"2025-11-25",
	"2026-07-28",
}

var supportedMCPRank = func() map[string]int {
	rank := make(map[string]int, len(supportedMCPVersions))
	for index, version := range supportedMCPVersions {
		rank[version] = index
	}
	return rank
}()

// CanonicalizeMCPVersions returns a copy sorted by pinned semantic order.
// Unsupported identifiers sort after supported revisions in lexical order;
// duplicates and exact spelling are preserved for later validation.
func CanonicalizeMCPVersions(versions []string) []string {
	result := append([]string(nil), versions...)
	sort.SliceStable(result, func(left, right int) bool {
		leftRank, leftSupported := supportedMCPRank[result[left]]
		rightRank, rightSupported := supportedMCPRank[result[right]]
		switch {
		case leftSupported && rightSupported:
			return leftRank < rightRank
		case leftSupported:
			return true
		case rightSupported:
			return false
		default:
			return result[left] < result[right]
		}
	})
	return result
}

// ValidateMCPVersions enforces the pinned revision vocabulary, non-empty list,
// and uniqueness. The list order does not matter.
func ValidateMCPVersions(versions []string) error {
	if len(versions) == 0 {
		return domain.Invalidf(opDecode, "mcp.versions must contain at least one supported protocol version")
	}
	seen := make(map[string]struct{}, len(versions))
	for _, version := range versions {
		if _, supported := supportedMCPRank[version]; !supported {
			return domain.Invalidf(opDecode, "unsupported MCP protocol version %q", version)
		}
		if _, duplicate := seen[version]; duplicate {
			return domain.Invalidf(opDecode, "duplicate MCP protocol version %q", version)
		}
		seen[version] = struct{}{}
	}
	return nil
}

func validateEndpointModes(endpoint NetworkEndpoint) error {
	if endpoint.TLS != "" && endpoint.TLS != "skip" {
		return domain.Invalidf(opDecode, "unknown tls value %q; omit the field to keep automatic TLS termination", endpoint.TLS)
	}
	switch endpoint.Enforcement {
	case "", "enforce", "audit":
	default:
		return domain.Invalidf(opDecode, "unknown enforcement value %q (expected enforce or audit)", endpoint.Enforcement)
	}
	switch endpoint.Access {
	case "", "read-only", "read-write", "full":
	default:
		return domain.Invalidf(opDecode, "unknown access value %q (expected read-only, read-write, or full)", endpoint.Access)
	}
	return nil
}

func (p *Policy) validateSemantics() error {
	if p == nil || !p.NetworkPolicies.HasValue() {
		return nil
	}
	for name, rule := range p.NetworkPolicies.Value {
		context := "network policy '" + name + "'"
		for _, endpoint := range rule.Endpoints {
			if err := validateEndpointModes(endpoint); err != nil {
				return err
			}
			if strings.EqualFold(endpoint.Protocol, "mcp") {
				if endpoint.MCP.HasValue() && endpoint.MCP.Value.Versions.HasValue() {
					if err := ValidateMCPVersions(endpoint.MCP.Value.Versions.Value); err != nil {
						return err
					}
				}
				continue
			}
			if endpoint.MCP.HasValue() {
				return domain.Invalidf(opDecode, "%s: non-MCP endpoint %q cannot configure mcp options", context, endpoint.Host)
			}
		}
	}
	return nil
}
