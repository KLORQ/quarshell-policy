package provider

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ParseYAML loads a profile from bytes.
func ParseYAML(b []byte) (Profile, error) {
	var p Profile
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return Profile{}, fmt.Errorf("provider profile: parse: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Profile{}, fmt.Errorf("provider profile: parse: multiple YAML documents are not supported")
		}
		return Profile{}, fmt.Errorf("provider profile: parse trailing document: %w", err)
	}
	// OpenShell omits TLS handling on L7 HTTPS endpoints and defaults them to
	// inspection. Apply that default before quarshell policy validation.
	for i := range p.Endpoints {
		if p.Endpoints[i].TLS == "" && p.Endpoints[i].Protocol != "" && p.Endpoints[i].Port == 443 {
			p.Endpoints[i].TLS = "terminate"
		}
	}
	if err := p.Validate(); err != nil {
		return Profile{}, err
	}
	return p, nil
}

// LoadFile reads a profile YAML file.
func LoadFile(path string) (Profile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, err
	}
	return ParseYAML(b)
}

// Catalog maps profile IDs to their validated definitions.
type Catalog = map[string]Profile

// LoadDir loads all *.yaml/*.yml profiles from a directory (non-recursive).
func LoadDir(dir string) (Catalog, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := Catalog{}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		p, err := LoadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		if _, exists := out[p.ID]; exists {
			return nil, fmt.Errorf("provider profile %q: duplicate ID in %s", p.ID, dir)
		}
		out[p.ID] = p
	}
	return out, nil
}
