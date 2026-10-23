package policy

import (
	"fmt"
	"sort"
	"strings"
)

// EffectivePorts returns ports, falling back to single Port.
func (r AllowRule) EffectivePorts() []int {
	if len(r.Ports) > 0 {
		return r.Ports
	}
	if r.Port != 0 {
		return []int{r.Port}
	}
	return nil
}

// TLSWarnings returns OpenShell-compatible advisory messages for deprecated
// TLS aliases and for tls:skip combined with L7 rules on port 443.

// TLSWarnings returns OpenShell-compatible advisory messages for deprecated
// TLS aliases and for tls:skip combined with L7 rules on port 443.
func (d Document) TLSWarnings() []string {
	var out []string
	seen := map[string]struct{}{}
	add := func(msg string) {
		if _, ok := seen[msg]; ok {
			return
		}
		seen[msg] = struct{}{}
		out = append(out, msg)
	}
	keys := make([]string, 0, len(d.NetworkPolicies))
	for k := range d.NetworkPolicies {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		np := d.NetworkPolicies[key]
		locBase := "network_policies." + key
		if np.Name != "" {
			locBase = "network_policies." + np.Name
		}
		for i, ep := range np.Endpoints {
			loc := fmt.Sprintf("%s.endpoints[%d]", locBase, i)
			tlsMode := strings.ToLower(strings.TrimSpace(ep.TLS))
			proto := strings.ToLower(strings.TrimSpace(ep.Protocol))
			switch tlsMode {
			case TLSTerminate:
				add("'tls: terminate' is deprecated; TLS termination is now automatic. Use 'tls: skip' to explicitly disable. This field will be removed in a future version.")
			case TLSPassthrough:
				add("'tls: passthrough' is deprecated; TLS termination is now automatic. Use 'tls: skip' to explicitly disable. This field will be removed in a future version.")
			}
			if tlsMode == "skip" && proto != "" {
				for _, port := range ep.EffectivePorts() {
					if port == 443 {
						add(fmt.Sprintf("%s: 'tls: skip' with L7 rules on port 443 — L7 inspection cannot work on encrypted traffic", loc))
						break
					}
				}
			}
		}
	}
	return out
}

// HardenMode returns best_effort|required from landlock.compatibility.

// HardenMode returns best_effort|required from landlock.compatibility.
func (d Document) HardenMode() string {
	if d.Landlock == nil {
		return "best_effort"
	}
	c := strings.ToLower(strings.TrimSpace(d.Landlock.Compatibility))
	if c == "hard_requirement" {
		return "required"
	}
	return "best_effort"
}

// FSRead returns filesystem_policy.read_only (nil-safe).

// FSRead returns filesystem_policy.read_only (nil-safe).
func (d Document) FSRead() []string {
	if d.FilesystemPolicy == nil {
		return nil
	}
	return d.FilesystemPolicy.ReadOnly
}

// FSWrite returns filesystem_policy.read_write (nil-safe).

// FSWrite returns filesystem_policy.read_write (nil-safe).
func (d Document) FSWrite() []string {
	if d.FilesystemPolicy == nil {
		return nil
	}
	return d.FilesystemPolicy.ReadWrite
}

// IncludeWorkdir reports filesystem_policy.include_workdir.

// IncludeWorkdir reports filesystem_policy.include_workdir.
func (d Document) IncludeWorkdir() bool {
	return d.FilesystemPolicy == nil || d.FilesystemPolicy.IncludeWorkdirEnabled()
}

// ProcessUser returns process.run_as_user.

// ProcessUser returns process.run_as_user.
func (d Document) ProcessUser() string {
	if d.Process == nil {
		return ""
	}
	return d.Process.RunAsUser
}

// ProcessGroup returns process.run_as_group.

// ProcessGroup returns process.run_as_group.
func (d Document) ProcessGroup() string {
	if d.Process == nil {
		return ""
	}
	return d.Process.RunAsGroup
}

// NetworkAllows flattens network_policies endpoints (no inference).

// NetworkAllows flattens network_policies endpoints (no inference).
func (d Document) NetworkAllows() []AllowRule {
	if len(d.NetworkPolicies) == 0 {
		return nil
	}
	// Stable-ish order: sort keys.
	keys := make([]string, 0, len(d.NetworkPolicies))
	for k := range d.NetworkPolicies {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []AllowRule
	for _, key := range keys {
		rule := d.NetworkPolicies[key]
		name := rule.Name
		if name == "" {
			name = key
		}
		bins := binaryPaths(rule.Binaries)
		for _, ep := range rule.Endpoints {
			r := ep
			r.networkPolicyKey = key
			r.networkPolicyName = rule.Name
			if r.ID == "" {
				r.ID = name
			}
			if len(r.Binaries) == 0 && len(bins) > 0 {
				r.Binaries = append([]string{}, bins...)
			}
			out = append(out, r)
		}
	}
	return out
}

// AllowRules returns network_policies endpoints plus expanded inference rules.

// AllowRules returns network_policies endpoints plus expanded inference rules.
func (d Document) AllowRules() []AllowRule {
	out := d.NetworkAllows()
	inf, err := ExpandInferenceRules(d.Inference)
	if err == nil {
		out = append(out, inf...)
	}
	return out
}

// SetNetworkAllows replaces network_policies with one entry per allow rule id.

// SetNetworkAllows replaces network_policies with one entry per allow rule id.
func (d *Document) SetNetworkAllows(rules []AllowRule) {
	if len(rules) == 0 {
		d.NetworkPolicies = nil
		return
	}
	out := make(map[string]NetworkPolicy, len(rules))
	for i, r := range rules {
		key := strings.TrimSpace(r.networkPolicyKey)
		if key == "" {
			key = strings.TrimSpace(r.ID)
		}
		if key == "" {
			key = fmt.Sprintf("rule_%d", i)
		}
		name := strings.TrimSpace(r.networkPolicyName)
		if name == "" {
			name = key
		}
		ep := r
		ep.ID = ""
		ep.networkPolicyKey = key
		ep.networkPolicyName = name
		bins := r.Binaries
		ep.Binaries = nil
		var nb []NetworkBinary
		for _, b := range bins {
			nb = append(nb, NetworkBinary{Path: b})
		}
		if existing, ok := out[key]; ok {
			existing.Endpoints = append(existing.Endpoints, ep)
			if len(existing.Binaries) == 0 {
				existing.Binaries = nb
			}
			out[key] = existing
			continue
		}
		out[key] = NetworkPolicy{
			Name:      name,
			Endpoints: []AllowRule{ep},
			Binaries:  nb,
		}
	}
	d.NetworkPolicies = out
}

// Enforcement modes.

func (f FilesystemPolicy) IncludeWorkdirEnabled() bool {
	return f.IncludeWorkdir || !f.IncludeWorkdirSet
}

// Landlock configures Landlock compatibility mode.

// Landlock configures Landlock compatibility mode.
