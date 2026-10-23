package policy

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// EndpointSpec is a parsed OpenShell-style --add-endpoint value:
//
//	host:port[:access[:protocol[:enforcement]]]
//
// Examples: api.github.com:443, api.example.com:443:read-only:rest:enforce
type EndpointSpec struct {
	Host        string
	Port        int
	Access      string
	Protocol    string
	Enforcement string
}

// ParseEndpointSpec parses an --add-endpoint argument.
func ParseEndpointSpec(spec string) (EndpointSpec, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return EndpointSpec{}, fmt.Errorf("policy: empty endpoint spec")
	}
	var parts []string
	if strings.HasPrefix(spec, "[") {
		end := strings.Index(spec, "]:")
		if end < 0 {
			return EndpointSpec{}, fmt.Errorf("policy: IPv6 endpoint needs [host]:port (got %q)", spec)
		}
		host := spec[1:end]
		if addr, err := netip.ParseAddr(host); err != nil || !addr.Is6() {
			return EndpointSpec{}, fmt.Errorf("policy: invalid IPv6 host in %q", spec)
		}
		parts = append([]string{host}, strings.Split(spec[end+2:], ":")...)
	} else {
		parts = strings.Split(spec, ":")
	}
	if len(parts) < 2 {
		return EndpointSpec{}, fmt.Errorf("policy: endpoint spec needs host:port (got %q)", spec)
	}
	host := strings.TrimSpace(parts[0])
	if host == "" {
		return EndpointSpec{}, fmt.Errorf("policy: empty host in %q", spec)
	}
	if len(parts) > 5 {
		return EndpointSpec{}, fmt.Errorf("policy: too many endpoint fields in %q", spec)
	}
	port, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || port <= 0 || port > 65535 {
		return EndpointSpec{}, fmt.Errorf("policy: invalid port in %q", spec)
	}
	out := EndpointSpec{Host: host, Port: port}
	if len(parts) > 2 {
		out.Access = strings.TrimSpace(parts[2])
	}
	if len(parts) > 3 {
		out.Protocol = strings.TrimSpace(parts[3])
	}
	if len(parts) > 4 {
		out.Enforcement = strings.TrimSpace(parts[4])
	}
	return out, nil
}

// MethodPathSpec is --add-allow / --add-deny: host:port:METHOD:path
type MethodPathSpec struct {
	Host   string
	Port   int
	Method string
	Path   string
}

// ParseMethodPathSpec parses host:port:METHOD:/path.
func ParseMethodPathSpec(spec string) (MethodPathSpec, error) {
	spec = strings.TrimSpace(spec)
	parts := strings.SplitN(spec, ":", 4)
	if len(parts) < 4 {
		return MethodPathSpec{}, fmt.Errorf("policy: method/path spec needs host:port:METHOD:path (got %q)", spec)
	}
	port, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil || port <= 0 {
		return MethodPathSpec{}, fmt.Errorf("policy: invalid port in %q", spec)
	}
	method := strings.TrimSpace(parts[2])
	path := strings.TrimSpace(parts[3])
	if method == "" || path == "" {
		return MethodPathSpec{}, fmt.Errorf("policy: method and path required in %q", spec)
	}
	return MethodPathSpec{
		Host:   strings.TrimSpace(parts[0]),
		Port:   port,
		Method: method,
		Path:   path,
	}, nil
}

// NetworkUpdate holds incremental network policy changes (OpenShell policy update).
type NetworkUpdate struct {
	AddEndpoints []EndpointSpec
	AddAllows    []MethodPathSpec
	AddDenies    []MethodPathSpec
	Binaries     []string // applied to newly added / matched endpoints
}

// ApplyNetworkUpdate merges u into a copy of base (network_policies endpoints).
func ApplyNetworkUpdate(base Document, u NetworkUpdate) (Document, error) {
	out := base
	allows := append([]AllowRule{}, out.NetworkAllows()...)

	for _, ep := range u.AddEndpoints {
		rule := AllowRule{
			Host:        ep.Host,
			Port:        ep.Port,
			Access:      ep.Access,
			Protocol:    ep.Protocol,
			Enforcement: ep.Enforcement,
			Binaries:    append([]string{}, u.Binaries...),
		}
		if rule.Protocol != "" || rule.Access != "" {
			rule.TLS = TLSTerminate
		}
		if idx := findAllowIndex(allows, ep.Host, ep.Port); idx >= 0 {
			merged := allows[idx]
			if rule.Access != "" {
				merged.Access = rule.Access
			}
			if rule.Protocol != "" {
				merged.Protocol = rule.Protocol
			}
			if rule.Enforcement != "" {
				merged.Enforcement = rule.Enforcement
			}
			if merged.Protocol != "" || merged.Access != "" || len(merged.Rules) > 0 {
				merged.TLS = TLSTerminate
			}
			merged.Binaries = mergeUnique(merged.Binaries, u.Binaries...)
			allows[idx] = merged
			continue
		}
		allows = append(allows, rule)
	}

	for _, a := range u.AddAllows {
		idx, next, err := ensureEndpoint(allows, a.Host, a.Port, u.Binaries)
		if err != nil {
			return Document{}, err
		}
		allows = next
		r := &allows[idx]
		r.Access = ""
		r.TLS = TLSTerminate
		r.Rules = append(r.Rules, L7Rule{Allow: &L7Allow{Method: a.Method, Path: a.Path}})
		if r.Protocol == "" {
			r.Protocol = ProtocolREST
		}
	}
	for _, d := range u.AddDenies {
		idx, next, err := ensureEndpoint(allows, d.Host, d.Port, u.Binaries)
		if err != nil {
			return Document{}, err
		}
		allows = next
		r := &allows[idx]
		r.Access = ""
		r.TLS = TLSTerminate
		r.DenyRules = append(r.DenyRules, L7DenyRule{Method: d.Method, Path: d.Path})
		if r.Protocol == "" {
			r.Protocol = ProtocolREST
		}
	}
	out.SetNetworkAllows(allows)
	if err := out.Validate(); err != nil {
		return Document{}, err
	}
	return out, nil
}

func findAllowIndex(rules []AllowRule, host string, port int) int {
	host = strings.ToLower(strings.TrimSpace(host))
	for i, r := range rules {
		if strings.ToLower(strings.TrimSpace(r.Host)) != host {
			continue
		}
		for _, effectivePort := range r.EffectivePorts() {
			if effectivePort == port {
				return i
			}
		}
	}
	return -1
}

func ensureEndpoint(allows []AllowRule, host string, port int, binaries []string) (int, []AllowRule, error) {
	if idx := findAllowIndex(allows, host, port); idx >= 0 {
		allows[idx].Binaries = mergeUnique(allows[idx].Binaries, binaries...)
		return idx, allows, nil
	}
	allows = append(allows, AllowRule{
		Host:     host,
		Port:     port,
		Protocol: "rest",
		Binaries: append([]string{}, binaries...),
	})
	return len(allows) - 1, allows, nil
}

func mergeUnique(base []string, extra ...string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(base)+len(extra))
	for _, s := range append(append([]string{}, base...), extra...) {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
