package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// Document is the canonical sandbox policy (OpenShell YAML naming).
func (d *Document) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return fmt.Errorf("policy: document must be a JSON object")
	}
	seen := map[string]struct{}{}
	versionPresent := false
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("policy: invalid JSON document")
		}
		key, ok := token.(string)
		if !ok {
			return fmt.Errorf("policy: document keys must be strings")
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("policy: duplicate field %q", key)
		}
		seen[key] = struct{}{}
		if key == "version" {
			versionPresent = true
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return fmt.Errorf("policy: invalid JSON document")
		}
		if key == "version" {
			var version uint32
			if string(value) == "null" || json.Unmarshal(value, &version) != nil {
				return fmt.Errorf("policy: version must be an unsigned 32-bit integer")
			}
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return fmt.Errorf("policy: invalid JSON document")
	}
	if !versionPresent {
		return fmt.Errorf("policy: missing required field %q", "version")
	}
	type documentAlias Document
	var decoded documentAlias
	strict := json.NewDecoder(bytes.NewReader(data))
	strict.DisallowUnknownFields()
	if err := strict.Decode(&decoded); err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	var trailing any
	if err := strict.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("policy: multiple JSON values")
	}
	*d = Document(decoded)
	return nil
}

// FilesystemPolicy is Landlock path policy + workdir include flag.

// FilesystemPolicy is Landlock path policy + workdir include flag.
func (f *FilesystemPolicy) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("filesystem_policy must be a mapping")
	}
	f.IncludeWorkdir = true
	seen := map[string]struct{}{}
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return fmt.Errorf("filesystem_policy keys must be strings")
		}
		if _, duplicate := seen[key.Value]; duplicate {
			return fmt.Errorf("filesystem_policy has duplicate field %q", key.Value)
		}
		seen[key.Value] = struct{}{}
		switch key.Value {
		case "include_workdir":
			if value.Tag != "!!bool" {
				return fmt.Errorf("filesystem_policy.include_workdir must be a boolean")
			}
			if err := value.Decode(&f.IncludeWorkdir); err != nil {
				return fmt.Errorf("filesystem_policy.include_workdir: %w", err)
			}
			f.IncludeWorkdirSet = true
		case "read_only":
			if value.Kind != yaml.SequenceNode {
				return fmt.Errorf("filesystem_policy.read_only must be a sequence")
			}
			if err := value.Decode(&f.ReadOnly); err != nil {
				return fmt.Errorf("filesystem_policy.read_only: %w", err)
			}
		case "read_write":
			if value.Kind != yaml.SequenceNode {
				return fmt.Errorf("filesystem_policy.read_write must be a sequence")
			}
			if err := value.Decode(&f.ReadWrite); err != nil {
				return fmt.Errorf("filesystem_policy.read_write: %w", err)
			}
		default:
			return fmt.Errorf("filesystem_policy has unknown field %q", key.Value)
		}
	}
	return nil
}

func (f FilesystemPolicy) MarshalYAML() (any, error) {
	type yamlFilesystemPolicy struct {
		IncludeWorkdir *bool    `yaml:"include_workdir,omitempty"`
		ReadOnly       []string `yaml:"read_only,omitempty"`
		ReadWrite      []string `yaml:"read_write,omitempty"`
	}
	var include *bool
	if f.IncludeWorkdirSet {
		include = &f.IncludeWorkdir
	}
	return yamlFilesystemPolicy{IncludeWorkdir: include, ReadOnly: f.ReadOnly, ReadWrite: f.ReadWrite}, nil
}

func (f *FilesystemPolicy) UnmarshalJSON(data []byte) error {
	type jsonFilesystemPolicy struct {
		IncludeWorkdir json.RawMessage `json:"include_workdir"`
		ReadOnly       json.RawMessage `json:"read_only"`
		ReadWrite      json.RawMessage `json:"read_write"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var value jsonFilesystemPolicy
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("filesystem_policy: multiple JSON values")
		}
		return err
	}
	f.IncludeWorkdir, f.IncludeWorkdirSet = true, false
	if len(value.IncludeWorkdir) != 0 {
		if string(value.IncludeWorkdir) == "null" {
			return fmt.Errorf("filesystem_policy.include_workdir must be a boolean")
		}
		if err := json.Unmarshal(value.IncludeWorkdir, &f.IncludeWorkdir); err != nil {
			return fmt.Errorf("filesystem_policy.include_workdir: %w", err)
		}
		f.IncludeWorkdirSet = true
	}
	if err := decodeFilesystemPathList("read_only", value.ReadOnly, &f.ReadOnly); err != nil {
		return err
	}
	if err := decodeFilesystemPathList("read_write", value.ReadWrite, &f.ReadWrite); err != nil {
		return err
	}
	return nil
}

func decodeFilesystemPathList(key string, raw json.RawMessage, target *[]string) error {
	if len(raw) == 0 {
		*target = nil
		return nil
	}
	if string(raw) == "null" {
		return fmt.Errorf("filesystem_policy.%s must be a sequence", key)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return fmt.Errorf("filesystem_policy.%s: %w", key, err)
	}
	return nil
}

func (f FilesystemPolicy) MarshalJSON() ([]byte, error) {
	type jsonFilesystemPolicy struct {
		IncludeWorkdir bool     `json:"include_workdir"`
		ReadOnly       []string `json:"read_only,omitempty"`
		ReadWrite      []string `json:"read_write,omitempty"`
	}
	return json.Marshal(jsonFilesystemPolicy{
		IncludeWorkdir: f.IncludeWorkdirEnabled(),
		ReadOnly:       f.ReadOnly,
		ReadWrite:      f.ReadWrite,
	})
}

func (l *Landlock) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("landlock must be a mapping")
	}
	l.Compatibility = "best_effort"
	seen := make(map[string]struct{}, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return fmt.Errorf("landlock keys must be strings")
		}
		if _, duplicate := seen[key.Value]; duplicate {
			return fmt.Errorf("landlock has duplicate field %q", key.Value)
		}
		seen[key.Value] = struct{}{}
		if key.Value != "compatibility" {
			return fmt.Errorf("landlock has unknown field %q", key.Value)
		}
		if value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
			return fmt.Errorf("landlock.compatibility must be a string")
		}
		if value.Value == "" {
			return fmt.Errorf("landlock.compatibility must be best_effort|hard_requirement")
		}
		l.Compatibility = value.Value
	}
	return nil
}

func (l *Landlock) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return fmt.Errorf("landlock must be an object")
	}
	l.Compatibility = "best_effort"
	seen := map[string]struct{}{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("landlock: invalid JSON object")
		}
		key, ok := token.(string)
		if !ok {
			return fmt.Errorf("landlock keys must be strings")
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("landlock has duplicate field %q", key)
		}
		seen[key] = struct{}{}
		if key != "compatibility" {
			return fmt.Errorf("landlock has unknown field %q", key)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil || string(value) == "null" {
			return fmt.Errorf("landlock.compatibility must be a string")
		}
		if err := json.Unmarshal(value, &l.Compatibility); err != nil {
			return fmt.Errorf("landlock.compatibility must be a string")
		}
		if l.Compatibility == "" {
			return fmt.Errorf("landlock.compatibility must be best_effort|hard_requirement")
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return fmt.Errorf("landlock: invalid JSON object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("landlock: multiple JSON values")
	}
	return nil
}

// Process is sandbox process identity (omit to let the compute driver choose).

// Process is sandbox process identity (omit to let the compute driver choose).
func (p *Process) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("process must be a mapping")
	}
	*p = Process{}
	seen := map[string]struct{}{}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return fmt.Errorf("process keys must be strings")
		}
		if _, duplicate := seen[key.Value]; duplicate {
			return fmt.Errorf("process has duplicate field %q", key.Value)
		}
		seen[key.Value] = struct{}{}
		if key.Value != "run_as_user" && key.Value != "run_as_group" {
			return fmt.Errorf("process has unknown field %q", key.Value)
		}
		if value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
			return fmt.Errorf("process.%s must be a string", key.Value)
		}
		if key.Value == "run_as_user" {
			p.RunAsUser = value.Value
		} else {
			p.RunAsGroup = value.Value
		}
	}
	return nil
}

func (p *Process) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return fmt.Errorf("process must be an object")
	}
	*p = Process{}
	seen := map[string]struct{}{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("process: invalid JSON object")
		}
		key, ok := token.(string)
		if !ok {
			return fmt.Errorf("process keys must be strings")
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("process has duplicate field %q", key)
		}
		seen[key] = struct{}{}
		if key != "run_as_user" && key != "run_as_group" {
			return fmt.Errorf("process has unknown field %q", key)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil || string(value) == "null" {
			return fmt.Errorf("process.%s must be a string", key)
		}
		var identity string
		if err := json.Unmarshal(value, &identity); err != nil {
			return fmt.Errorf("process.%s must be a string", key)
		}
		if key == "run_as_user" {
			p.RunAsUser = identity
		} else {
			p.RunAsGroup = identity
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return fmt.Errorf("process: invalid JSON object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("process: multiple JSON values")
	}
	return nil
}

// NetworkPolicy is one named egress policy (map value under network_policies).

// NetworkPolicy is one named egress policy (map value under network_policies).
