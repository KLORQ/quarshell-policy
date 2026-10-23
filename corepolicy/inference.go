package policy

import (
	"fmt"
	"slices"
	"strings"

	"github.com/KLORQ/quarshell-core/defaults"
)

// Inference names known LLM/API destinations (expanded into egress allow rules).
type Inference struct {
	// Providers are builtin preset ids (anthropic, openai, …).
	Providers []string `yaml:"providers,omitempty" json:"providers,omitempty"`
	// Profiles are named custom providers (Providers v2).
	Profiles []ProviderProfile `yaml:"profiles,omitempty" json:"profiles,omitempty"`
	// Allow is extra host/port rules (same shape as network_policies endpoints).
	Allow []AllowRule `yaml:"allow,omitempty" json:"allow,omitempty"`
}

// ProviderProfile is a user-defined inference endpoint set (P10).
type ProviderProfile struct {
	ID      string      `yaml:"id" json:"id"`
	Host    string      `yaml:"host,omitempty" json:"host,omitempty"`
	Port    int         `yaml:"port,omitempty" json:"port,omitempty"`
	Ports   []int       `yaml:"ports,omitempty" json:"ports,omitempty"`
	EnvKeys []string    `yaml:"env_keys,omitempty" json:"env_keys,omitempty"`
	Refresh string      `yaml:"refresh,omitempty" json:"refresh,omitempty"` // env | none
	Hosts   []AllowRule `yaml:"hosts,omitempty" json:"hosts,omitempty"`     // multi-host alternative
}

// ProviderPreset is one builtin inference provider.
type ProviderPreset struct {
	ID      string
	Rules   []AllowRule
	EnvKeys []string // host env injected when this provider is selected
}

// BuiltinProviders is the product catalog of inference provider presets.
var BuiltinProviders = map[string]ProviderPreset{
	"anthropic": {
		ID: "anthropic",
		Rules: []AllowRule{{
			ID: "inference.anthropic", Host: "api.anthropic.com", Port: 443,
			Protocol: ProtocolREST, TLS: TLSTerminate, Access: AccessReadWrite,
			CredentialKeys: []string{"ANTHROPIC_API_KEY"},
		}},
		EnvKeys: []string{"ANTHROPIC_API_KEY"},
	},
	"openai": {
		ID: "openai",
		Rules: []AllowRule{{
			ID: "inference.openai", Host: "*.openai.com", Ports: []int{443},
			Protocol: ProtocolREST, TLS: TLSTerminate, Access: AccessReadWrite,
			CredentialKeys: []string{"OPENAI_API_KEY"},
		}},
		EnvKeys: []string{"OPENAI_API_KEY"},
	},
	"openrouter": {
		ID: "openrouter",
		Rules: []AllowRule{{
			ID: "inference.openrouter", Host: "openrouter.ai", Port: 443,
			Protocol: ProtocolREST, TLS: TLSTerminate, Access: AccessReadWrite,
			CredentialKeys: []string{"OPENROUTER_API_KEY"},
		}},
		EnvKeys: []string{"OPENROUTER_API_KEY"},
	},
	"google": {
		ID: "google",
		Rules: []AllowRule{{
			ID: "inference.google", Host: "generativelanguage.googleapis.com", Port: 443,
			Protocol: ProtocolREST, TLS: TLSTerminate, Access: AccessReadWrite,
			CredentialKeys: []string{"GOOGLE_API_KEY", "GEMINI_API_KEY"},
		}},
		EnvKeys: []string{"GOOGLE_API_KEY", "GEMINI_API_KEY"},
	},
	"groq": {
		ID: "groq",
		Rules: []AllowRule{{
			ID: "inference.groq", Host: "api.groq.com", Port: 443,
			Protocol: ProtocolREST, TLS: TLSTerminate, Access: AccessReadWrite,
			CredentialKeys: []string{"GROQ_API_KEY"},
		}},
		EnvKeys: []string{"GROQ_API_KEY"},
	},
	// Host-backed models also accept the legacy host.openshell.internal alias.
	"local": {
		ID: "local",
		Rules: []AllowRule{
			{ID: "inference.host-local", Host: defaults.HostInternal, Ports: []int{11434, 1234, 8000, 8080}},
		},
		EnvKeys: nil,
	},
}

// BuiltinProviderPresets maps id → allow rules (compat helper).
var BuiltinProviderPresets = func() map[string][]AllowRule {
	m := make(map[string][]AllowRule, len(BuiltinProviders))
	for id, p := range BuiltinProviders {
		m[id] = p.Rules
	}
	return m
}()

// KnownProviderIDs returns sorted builtin provider ids.
func KnownProviderIDs() []string {
	out := make([]string, 0, len(BuiltinProviders))
	for id := range BuiltinProviders {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

// ExpandInferenceRules returns allow rules from inference.providers + profiles + allow.
func ExpandInferenceRules(inf *Inference) ([]AllowRule, error) {
	if inf == nil {
		return nil, nil
	}
	var out []AllowRule
	for i, raw := range inf.Providers {
		id := strings.ToLower(strings.TrimSpace(raw))
		if id == "" {
			return nil, fmt.Errorf("policy: inference.providers[%d]: empty id", i)
		}
		preset, ok := BuiltinProviders[id]
		if !ok {
			return nil, fmt.Errorf("policy: inference.providers[%d]: unknown %q (known: %s)", i, raw, strings.Join(KnownProviderIDs(), ", "))
		}
		out = append(out, preset.Rules...)
	}
	for i, p := range inf.Profiles {
		id := strings.TrimSpace(p.ID)
		if id == "" {
			return nil, fmt.Errorf("policy: inference.profiles[%d]: id required", i)
		}
		switch strings.ToLower(strings.TrimSpace(p.Refresh)) {
		case "", "env", "none":
		default:
			return nil, fmt.Errorf("policy: inference.profiles[%d]: refresh must be env|none", i)
		}
		if len(p.Hosts) > 0 {
			for j, h := range p.Hosts {
				rule := h
				if rule.ID == "" {
					rule.ID = "inference.profile." + id
				}
				if strings.TrimSpace(rule.Host) == "" {
					return nil, fmt.Errorf("policy: inference.profiles[%d].hosts[%d]: host required", i, j)
				}
				if len(rule.CredentialKeys) == 0 && len(p.EnvKeys) > 0 {
					rule.CredentialKeys = append([]string{}, p.EnvKeys...)
				}
				out = append(out, rule)
			}
			continue
		}
		if strings.TrimSpace(p.Host) == "" {
			return nil, fmt.Errorf("policy: inference.profiles[%d]: host or hosts required", i)
		}
		rule := AllowRule{
			ID:             "inference.profile." + id,
			Host:           p.Host,
			Port:           p.Port,
			Ports:          append([]int{}, p.Ports...),
			CredentialKeys: append([]string{}, p.EnvKeys...),
		}
		out = append(out, rule)
	}
	out = append(out, inf.Allow...)
	return out, nil
}

// EnvKeysForInference returns credential env names implied by selected providers + profiles.
func EnvKeysForInference(inf *Inference) []string {
	if inf == nil {
		return nil
	}
	var out []string
	seen := map[string]struct{}{}
	add := func(keys []string) {
		for _, k := range keys {
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, k)
		}
	}
	for _, raw := range inf.Providers {
		id := strings.ToLower(strings.TrimSpace(raw))
		p, ok := BuiltinProviders[id]
		if !ok {
			continue
		}
		add(p.EnvKeys)
	}
	for _, p := range inf.Profiles {
		add(p.EnvKeys)
	}
	return out
}

// CredentialEnvKeys merges credentials.env_allow with provider-implied keys.
func (d Document) CredentialEnvKeys() []string {
	var out []string
	seen := map[string]struct{}{}
	add := func(keys []string) {
		for _, k := range keys {
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			if _, ok := seen[k]; ok {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, k)
		}
	}
	if d.Credentials != nil {
		add(d.Credentials.EnvAllow)
	}
	add(EnvKeysForInference(d.Inference))
	return out
}
