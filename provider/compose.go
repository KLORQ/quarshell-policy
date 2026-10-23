package provider

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/KLORQ/quarshell-policy/corepolicy"
)

// Layer is one attached provider contribution.
type Layer struct {
	InstanceName string
	Profile      Profile
	EnvVars      []string // instance override; empty → profile defaults
}

// OmitProviderComposed removes network_policies rules whose id is prefixed with
// "provider." (stamped by EffectivePolicy). Use when accepting a policy set that may have
// been edited from `policy get --full` so provider-composed entries are not duplicated
// into the durable base when edit --base is selected, not --full.
func OmitProviderComposed(doc policy.Document) (policy.Document, int) {
	allows := doc.NetworkAllows()
	if len(allows) == 0 {
		return doc, 0
	}
	kept := make([]policy.AllowRule, 0, len(allows))
	n := 0
	for _, r := range allows {
		id := strings.TrimSpace(r.ID)
		if strings.HasPrefix(id, "provider.") {
			n++
			continue
		}
		kept = append(kept, r)
	}
	if n == 0 {
		return doc, 0
	}
	out := doc
	out.SetNetworkAllows(kept)
	return out, n
}

// EffectivePolicy is the OpenShell composition step: effective policy =
// base + provider-composed profile entries (unless suppressProviders).
func composeProviderLayers(base policy.Document, layers []Layer, suppressProviders bool) policy.Document {
	out := base
	allows := append([]policy.AllowRule{}, out.NetworkAllows()...)
	if out.Credentials == nil {
		out.Credentials = &policy.Credentials{}
	} else {
		credCopy := *out.Credentials
		credCopy.EnvAllow = append([]string{}, out.Credentials.EnvAllow...)
		out.Credentials = &credCopy
	}
	if suppressProviders {
		out.SetNetworkAllows(allows)
		return out
	}
	envSeen := map[string]struct{}{}
	for _, k := range out.Credentials.EnvAllow {
		envSeen[k] = struct{}{}
	}
	for _, layer := range layers {
		p := layer.Profile
		keys := layer.EnvVars
		if len(keys) == 0 {
			keys = p.EnvKeys()
		}
		guestKeys := p.GuestEnvKeys()
		if len(layer.EnvVars) > 0 {
			// Instance override: still honor profile inject_env:false exclusions.
			omit := map[string]struct{}{}
			for _, c := range p.Credentials {
				if c.InjectEnv != nil && !*c.InjectEnv {
					for _, k := range c.EnvVars {
						omit[strings.TrimSpace(k)] = struct{}{}
					}
				}
			}
			guestKeys = nil
			for _, k := range keys {
				if _, skip := omit[k]; skip {
					continue
				}
				guestKeys = append(guestKeys, k)
			}
		}
		for i, ep := range p.Endpoints {
			rule := ep
			if rule.ID == "" {
				rule.ID = fmt.Sprintf("provider.%s.%d", layer.InstanceName, i)
			} else {
				rule.ID = fmt.Sprintf("provider.%s.%s", layer.InstanceName, rule.ID)
			}
			if len(rule.Binaries) == 0 && len(p.Binaries) > 0 {
				rule.Binaries = append([]string{}, p.Binaries...)
			}
			rule.CredentialKeys = append([]string{}, keys...)
			allows = append(allows, rule)
		}
		for _, k := range guestKeys {
			if _, ok := envSeen[k]; ok {
				continue
			}
			envSeen[k] = struct{}{}
			out.Credentials.EnvAllow = append(out.Credentials.EnvAllow, k)
		}
	}
	out.SetNetworkAllows(allows)
	return out
}

// EffectivePolicy composes provider endpoint credentials and resolves
// sandbox-scoped OpenShell credential_binding references. Bindings fail closed
// unless the named attached instance has an endpointless profile that declares
// credential keys for guest injection and endpoint-scoped proxy rewriting.
func EffectivePolicy(base policy.Document, layers []Layer, suppressProviders bool) (policy.Document, error) {
	out := composeProviderLayers(base, layers, suppressProviders)
	layersByName := make(map[string]Layer, len(layers))
	for _, layer := range layers {
		name := strings.TrimSpace(layer.InstanceName)
		if name == "" {
			return policy.Document{}, fmt.Errorf("provider composition: instance name required")
		}
		if _, exists := layersByName[name]; exists {
			return policy.Document{}, fmt.Errorf("provider composition: duplicate attached provider instance %q", name)
		}
		layersByName[name] = layer
	}

	rules := out.NetworkAllows()
	if out.Credentials == nil {
		out.Credentials = &policy.Credentials{}
	}
	envSeen := make(map[string]struct{}, len(out.Credentials.EnvAllow))
	for _, key := range out.Credentials.EnvAllow {
		envSeen[key] = struct{}{}
	}
	for i := range rules {
		binding := rules[i].CredentialBinding
		if binding == nil {
			continue
		}
		providerName := binding.Provider
		layer, ok := layersByName[providerName]
		if !ok {
			return policy.Document{}, fmt.Errorf("credential_binding.provider %q is not attached to this sandbox", providerName)
		}
		if len(layer.Profile.Endpoints) != 0 {
			return policy.Document{}, fmt.Errorf("credential_binding.provider %q must use an endpointless provider profile", providerName)
		}
		declared := layer.Profile.EnvKeys()
		if len(declared) == 0 {
			return policy.Document{}, fmt.Errorf("credential_binding.provider %q profile declares no credentials", providerName)
		}
		declaredSet := make(map[string]struct{}, len(declared))
		for _, key := range declared {
			declaredSet[key] = struct{}{}
		}
		keys := append([]string(nil), layer.EnvVars...)
		if len(keys) == 0 {
			keys = declared
		}
		selectedKeys := make(map[string]struct{}, len(keys))
		boundKeys := make([]string, 0, len(keys))
		for _, key := range keys {
			key = strings.TrimSpace(key)
			if _, ok := declaredSet[key]; !ok {
				return policy.Document{}, fmt.Errorf("credential_binding.provider %q does not declare credential %q", providerName, key)
			}
			if _, duplicate := selectedKeys[key]; duplicate {
				continue
			}
			selectedKeys[key] = struct{}{}
			boundKeys = append(boundKeys, key)
		}
		if len(boundKeys) == 0 {
			return policy.Document{}, fmt.Errorf("credential_binding.provider %q has no selected credentials", providerName)
		}
		rules[i].CredentialKeys = boundKeys
		for _, key := range layer.Profile.GuestEnvKeys() {
			if _, selected := selectedKeys[key]; !selected {
				continue
			}
			if _, seen := envSeen[key]; seen {
				continue
			}
			envSeen[key] = struct{}{}
			out.Credentials.EnvAllow = append(out.Credentials.EnvAllow, key)
		}
	}
	out.SetNetworkAllows(rules)
	if err := out.Validate(); err != nil {
		return policy.Document{}, err
	}
	return out, nil
}

// FindBuiltinDir locates a providers catalog directory (cwd or next to the executable).
func FindBuiltinDir() string {
	candidates := []string{}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(wd, "quarshell-policy", "profiles"),
			filepath.Join(wd, "quarshell-cli", "providers"),
			filepath.Join(wd, "providers"),
			filepath.Join(wd, "profiles"),
		)
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, "profiles"),
			filepath.Join(dir, "providers"),
			filepath.Join(dir, "..", "profiles"),
			filepath.Join(dir, "..", "providers"),
			filepath.Join(dir, "..", "quarshell-policy", "profiles"),
			filepath.Join(dir, "..", "quarshell-cli", "providers"),
		)
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return ""
}
