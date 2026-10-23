package provider

import (
	"os"
	"strings"
)

// EnvKeys returns all credential env var names from the profile.
func (p Profile) EnvKeys() []string {
	var out []string
	seen := map[string]struct{}{}
	for _, c := range p.Credentials {
		for _, k := range c.EnvVars {
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
	return out
}

// DiscoveryCredentials returns the selected credential definitions in discovery order.
func (p Profile) DiscoveryCredentials() []Credential {
	byName := make(map[string]Credential, len(p.Credentials))
	for _, credential := range p.Credentials {
		byName[strings.TrimSpace(credential.Name)] = credential
	}
	out := make([]Credential, 0, len(p.Discovery.Credentials))
	for _, name := range p.Discovery.Credentials {
		if credential, ok := byName[strings.TrimSpace(name)]; ok {
			out = append(out, credential)
		}
	}
	return out
}

// GuestEnvKeys returns credential env keys that should be injected into the guest
// as quarshell:resolve:env placeholders (excludes inject_env: false).
func (p Profile) GuestEnvKeys() []string {
	var out []string
	seen := map[string]struct{}{}
	for _, c := range p.Credentials {
		if c.InjectEnv != nil && !*c.InjectEnv {
			continue
		}
		for _, k := range c.EnvVars {
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
	return out
}

// DiscoverEnvVars picks host env keys for a provider instance (OpenShell --from-existing).
// Every non-empty alias of each selected credential is discovered. Required flags
// do not restrict discovery. Empty discovery is
// successful with no matches. Values are never returned — only key names.
func (p Profile) DiscoverEnvVars() ([]string, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	var out []string
	seen := map[string]struct{}{}
	for _, c := range p.DiscoveryCredentials() {
		for _, k := range c.EnvVars {
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			if _, scanned := seen[k]; scanned {
				continue
			}
			seen[k] = struct{}{}
			if v, ok := os.LookupEnv(k); ok && strings.TrimSpace(v) != "" {
				// Host may leak guest placeholders into the process env — treat as missing.
				if strings.HasPrefix(strings.TrimSpace(v), "quarshell:resolve:env:") ||
					strings.HasPrefix(strings.TrimSpace(v), "openshell:resolve:env:") {
					continue
				}
				out = append(out, k)
			}
		}
	}
	return out, nil
}

// DiscoverConfig collects the non-secret configuration variables discovered by
// the pinned OpenShell Vertex AI profile. Other profiles discover no config.
func (p Profile) DiscoverConfig() map[string]string {
	if p.ID != "google-vertex-ai" {
		return nil
	}
	config := map[string]string{}
	for _, key := range []string{"VERTEX_AI_PROJECT_ID", "VERTEX_AI_REGION", "GOOGLE_VERTEX_AI_BASE_URL", "VERTEX_AI_BASE_URL", "VERTEX_AI_PUBLISHER"} {
		if value, ok := os.LookupEnv(key); ok && strings.TrimSpace(value) != "" {
			config[key] = value
		}
	}
	return config
}
