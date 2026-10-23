// Package prover implements bounded policy containment checks. It is
// deliberately conservative: Unsupported and Inconclusive never allow.
package prover

import (
	"path"
	"sort"
	"strings"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-policy"
)

// Relation is the containment result.
type Relation string

const (
	Within       Relation = "within"
	Exceeds      Relation = "exceeds"
	Unsupported  Relation = "unsupported"
	Inconclusive Relation = "inconclusive"
)

// Report is one containment result. Only Within allows activation.
type Report struct {
	Relation       Relation
	Reasons        []string
	Counterexample []string
}

// Allows reports whether the requested policy is contained.
func (r Report) Allows() bool { return r.Relation == Within }

// Query compares a requested policy against an allowed policy.
type Query struct {
	Allowed   *policy.Policy
	Requested *policy.Policy
}

// Containment checks filesystem, process, and network containment. It does not
// claim completeness for unimplemented matchers; those return Inconclusive.
func Containment(query Query) (Report, error) {
	if query.Allowed == nil || query.Requested == nil {
		return Report{}, domain.Invalidf("prover.containment", "allowed and requested policies are required")
	}
	report := Report{Relation: Within}
	containmentCheck(query, &report)
	return report, nil
}

func containmentCheck(query Query, report *Report) {
	checkFilesystem(query, report)
	checkProcess(query, report)
	checkNetwork(query, report)
}

func checkFilesystem(query Query, report *Report) {
	if !query.Requested.Filesystem.HasValue() {
		return
	}
	allowedRead, allowedWrite := allowedFilesystem(query.Allowed)
	for _, path := range query.Requested.Filesystem.Value.ReadOnly {
		checkPath(allowedRead, path, "read", report)
	}
	for _, path := range query.Requested.Filesystem.Value.ReadWrite {
		checkPath(allowedWrite, path, "write", report)
	}
}

func allowedFilesystem(allowed *policy.Policy) (read, write []string) {
	if !allowed.Filesystem.HasValue() {
		return nil, nil
	}
	read = append(read, allowed.Filesystem.Value.ReadOnly...)
	read = append(read, allowed.Filesystem.Value.ReadWrite...)
	write = append(write, allowed.Filesystem.Value.ReadWrite...)
	return read, write
}

func checkPath(allowed []string, requested, mode string, report *Report) {
	clean := path.Clean(requested)
	if strings.ContainsAny(requested, "*?") {
		report.raise(Inconclusive, "filesystem "+mode+" path uses a wildcard", requested)
		return
	}
	for _, candidate := range allowed {
		if strings.ContainsAny(candidate, "*?") {
			report.raise(Inconclusive, "allowed filesystem path uses a wildcard", candidate)
			return
		}
		cleanCandidate := path.Clean(candidate)
		if clean == cleanCandidate || strings.HasPrefix(clean, strings.TrimSuffix(cleanCandidate, "/")+"/") {
			return
		}
	}
	report.raise(Exceeds, "requested "+mode+" path is outside the allowed grants", requested)
}

func checkProcess(query Query, report *Report) {
	requested := query.Requested.Process
	if !requested.HasValue() {
		return
	}
	allowed := query.Allowed.Process
	if !allowed.HasValue() {
		return
	}
	for field, values := range map[string][2]domain.Field[string]{
		"run_as_user":  {allowed.Value.RunAsUser, requested.Value.RunAsUser},
		"run_as_group": {allowed.Value.RunAsGroup, requested.Value.RunAsGroup},
	} {
		if !values[0].HasValue() {
			continue
		}
		if !values[1].HasValue() {
			report.raise(Inconclusive, "requested process identity is omitted while allowed identity is fixed", field)
			continue
		}
		if values[0].Value != values[1].Value {
			report.raise(Exceeds, "requested process identity differs from the allowed identity", field)
		}
	}
}

func checkNetwork(query Query, report *Report) {
	if !query.Requested.NetworkPolicies.HasValue() || len(query.Requested.NetworkPolicies.Value) == 0 {
		return
	}
	if !query.Allowed.NetworkPolicies.HasValue() || len(query.Allowed.NetworkPolicies.Value) == 0 {
		report.raise(Exceeds, "requested policy has network rules but the allowed policy has none", "network_policies")
		return
	}
	allowedEndpoints := flattenEndpoints(query.Allowed)
	names := make([]string, 0, len(query.Requested.NetworkPolicies.Value))
	for name := range query.Requested.NetworkPolicies.Value {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, endpoint := range query.Requested.NetworkPolicies.Value[name].Endpoints {
			if !coveredByAny(allowedEndpoints, endpoint, report) {
				report.raise(Exceeds, "requested endpoint is not covered by the allowed policy", endpointHost(endpoint))
			}
		}
	}
}

func flattenEndpoints(p *policy.Policy) []policy.NetworkEndpoint {
	if !p.NetworkPolicies.HasValue() {
		return nil
	}
	var result []policy.NetworkEndpoint
	for _, rule := range p.NetworkPolicies.Value {
		result = append(result, rule.Endpoints...)
	}
	return result
}

func coveredByAny(allowed []policy.NetworkEndpoint, requested policy.NetworkEndpoint, report *Report) bool {
	for _, candidate := range allowed {
		covered, inconclusive := endpointCovers(candidate, requested)
		if inconclusive {
			report.raise(Inconclusive, "endpoint matcher is too complex for bounded containment", endpointHost(requested))
			return true
		}
		if covered {
			return true
		}
	}
	return false
}

func endpointCovers(allowed, requested policy.NetworkEndpoint) (bool, bool) {
	if allowed.Protocol != "" && !strings.EqualFold(allowed.Protocol, requested.Protocol) {
		return false, false
	}
	if !hostCovers(allowed.Host, requested.Host) {
		return false, false
	}
	if !portsCovered(allowed, requested) {
		return false, false
	}
	if len(requested.Rules) > 0 || len(requested.DenyRules) > 0 {
		if len(allowed.Rules) > 0 || len(allowed.DenyRules) > 0 {
			return false, true
		}
		if allowed.Access == "" || allowed.Access == "full" {
			return true, false
		}
		return false, false
	}
	if len(allowed.Rules) > 0 || len(allowed.DenyRules) > 0 {
		return false, false
	}
	if !accessCovers(allowed.Access, requested.Access) {
		return false, false
	}
	return true, false
}

func hostCovers(allowed, requested string) bool {
	allowed = strings.ToLower(strings.TrimSpace(allowed))
	requested = strings.ToLower(strings.TrimSpace(requested))
	if allowed == "*" || allowed == "**" {
		return true
	}
	if allowed == requested {
		return true
	}
	if strings.HasPrefix(allowed, "**.") {
		suffix := allowed[2:]
		return strings.HasSuffix(requested, suffix)
	}
	if strings.HasPrefix(allowed, "*.") {
		if strings.HasPrefix(requested, "*.") || strings.HasPrefix(requested, "**.") {
			return requested == allowed
		}
		suffix := allowed[1:]
		if !strings.HasSuffix(requested, suffix) {
			return false
		}
		remainder := strings.TrimSuffix(requested, suffix)
		return !strings.Contains(remainder, ".")
	}
	return false
}

func portsCovered(allowed, requested policy.NetworkEndpoint) bool {
	allowedPorts := effectivePorts(allowed)
	requestedPorts := effectivePorts(requested)
	if len(allowedPorts) == 0 || len(requestedPorts) == 0 {
		return false
	}
	set := make(map[uint16]struct{}, len(allowedPorts))
	for _, port := range allowedPorts {
		set[port] = struct{}{}
	}
	for _, port := range requestedPorts {
		if _, ok := set[port]; !ok {
			return false
		}
	}
	return true
}

func effectivePorts(endpoint policy.NetworkEndpoint) []uint16 {
	if len(endpoint.Ports) > 0 {
		return endpoint.Ports
	}
	if endpoint.Port.HasValue() && endpoint.Port.Value != 0 {
		return []uint16{endpoint.Port.Value}
	}
	return nil
}

func accessCovers(allowed, requested string) bool {
	if allowed == requested || allowed == "full" || allowed == "" {
		return true
	}
	if allowed == "read-write" && requested == "read-only" {
		return true
	}
	return false
}

func endpointHost(endpoint policy.NetworkEndpoint) string {
	if endpoint.Host == "" {
		return "<no host>"
	}
	return endpoint.Host
}

func (r *Report) raise(relation Relation, reason, example string) {
	if rank(relation) > rank(r.Relation) {
		r.Relation = relation
	}
	r.Reasons = append(r.Reasons, reason)
	if example != "" {
		r.Counterexample = append(r.Counterexample, example)
	}
}

func rank(relation Relation) int {
	switch relation {
	case Exceeds:
		return 4
	case Unsupported:
		return 3
	case Inconclusive:
		return 2
	case Within:
		return 1
	default:
		return 0
	}
}
