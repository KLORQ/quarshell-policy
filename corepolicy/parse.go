package policy

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// Load reads and parses a policy YAML file.
func Load(path string) (Document, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Document{}, err
	}
	return Parse(b)
}

// Parse unmarshals OpenShell-shaped policy YAML.

// Parse unmarshals OpenShell-shaped policy YAML.
func Parse(data []byte) (Document, error) {
	if err := rejectRemovedSchema(data); err != nil {
		return Document{}, err
	}
	if _, err := parseRequiredVersion(data); err != nil {
		return Document{}, err
	}
	var d Document
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&d); err != nil {
		return Document{}, fmt.Errorf("policy: parse: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Document{}, fmt.Errorf("policy: parse: multiple YAML documents are not supported")
		}
		return Document{}, fmt.Errorf("policy: parse trailing document: %w", err)
	}
	if err := validateNetworkMiddlewareSchema(data); err != nil {
		return Document{}, err
	}
	return d, nil
}

// parseRequiredVersion mirrors the pinned OpenShell PolicyFile's required u32
// field. yaml.v3 accepts missing/null scalar fields into Go's zero values, so
// validate presence, duplicate keys and the unsigned width before decoding the
// full document.

// parseRequiredVersion mirrors the pinned OpenShell PolicyFile's required u32
// field. yaml.v3 accepts missing/null scalar fields into Go's zero values, so
// validate presence, duplicate keys and the unsigned width before decoding the
// full document.
func parseRequiredVersion(data []byte) (uint32, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return 0, nil // The strict document decoder below reports syntax errors.
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return 0, fmt.Errorf("policy: root must be a mapping with required version")
	}
	var versionNode *yaml.Node
	seenFields := make(map[string]struct{}, len(root.Content[0].Content)/2)
	content := root.Content[0].Content
	for i := 0; i+1 < len(content); i += 2 {
		key, value := content[i], content[i+1]
		if key.Kind == yaml.ScalarNode && key.Tag == "!!str" {
			if _, duplicate := seenFields[key.Value]; duplicate {
				return 0, fmt.Errorf("policy: duplicate field %q", key.Value)
			}
			seenFields[key.Value] = struct{}{}
			if key.Value == "version" {
				versionNode = value
			}
		}
	}
	if versionNode == nil {
		return 0, fmt.Errorf("policy: missing required field %q", "version")
	}
	if versionNode.Kind != yaml.ScalarNode || versionNode.Tag != "!!int" {
		return 0, fmt.Errorf("policy: version must be an unsigned 32-bit integer")
	}
	var version uint32
	if err := versionNode.Decode(&version); err != nil {
		return 0, fmt.Errorf("policy: version must be an unsigned 32-bit integer")
	}
	return version, nil
}

// rejectRemovedSchema fails closed on the removed keys (filesystem / network).

// rejectRemovedSchema fails closed on the removed keys (filesystem / network).
func rejectRemovedSchema(data []byte) error {
	var probe struct {
		Filesystem yaml.Node `yaml:"filesystem"`
		Network    yaml.Node `yaml:"network"`
	}
	if err := yaml.Unmarshal(data, &probe); err != nil {
		return nil
	}
	if probe.Filesystem.Kind != 0 {
		return fmt.Errorf("policy: key \"filesystem\" removed; use filesystem_policy / landlock")
	}
	if probe.Network.Kind != 0 {
		return fmt.Errorf("policy: key \"network\" removed; use network_policies")
	}
	return nil
}

func validateNetworkMiddlewareSchema(data []byte) error {
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil || len(document.Content) == 0 {
		return nil // The strict document decoder above reports syntax and shape errors.
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil
	}
	middlewares, ok, err := yamlMappingField(root, "network_middlewares", "policy")
	if err != nil || !ok {
		return err
	}
	if middlewares.Kind != yaml.MappingNode {
		return fmt.Errorf("policy: network_middlewares must be a mapping")
	}
	seen := map[string]struct{}{}
	for i := 0; i < len(middlewares.Content); i += 2 {
		key, value := middlewares.Content[i], middlewares.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return fmt.Errorf("policy: network_middlewares keys must be strings")
		}
		if _, duplicate := seen[key.Value]; duplicate {
			return fmt.Errorf("policy: network_middlewares has duplicate key %q", key.Value)
		}
		seen[key.Value] = struct{}{}
		if err := validateNetworkMiddlewareEntry(key.Value, value); err != nil {
			return err
		}
	}
	return nil
}

func validateNetworkMiddlewareEntry(name string, node *yaml.Node) error {
	prefix := fmt.Sprintf("policy: network_middlewares.%s", name)
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("%s must be an object", prefix)
	}
	allowed := map[string]bool{"name": true, "middleware": true, "order": true, "config": true, "on_error": true, "endpoints": true}
	fields := map[string]*yaml.Node{}
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return fmt.Errorf("%s field names must be strings", prefix)
		}
		if !allowed[key.Value] {
			return fmt.Errorf("%s has unknown field %q", prefix, key.Value)
		}
		if _, duplicate := fields[key.Value]; duplicate {
			return fmt.Errorf("%s has duplicate field %q", prefix, key.Value)
		}
		fields[key.Value] = value
	}
	if _, ok := fields["middleware"]; !ok {
		return fmt.Errorf("%s.middleware is required", prefix)
	}
	for _, key := range []string{"name", "middleware", "on_error"} {
		if value, ok := fields[key]; ok && (value.Kind != yaml.ScalarNode || value.Tag != "!!str") {
			return fmt.Errorf("%s.%s must be a string", prefix, key)
		}
	}
	if order, ok := fields["order"]; ok {
		var value int32
		if order.Kind != yaml.ScalarNode || order.Tag != "!!int" || order.Decode(&value) != nil {
			return fmt.Errorf("%s.order must be an i32", prefix)
		}
	}
	if config, ok := fields["config"]; ok {
		if config.Kind != yaml.MappingNode {
			return fmt.Errorf("%s.config must be an object", prefix)
		}
		if err := validateJSONCompatibleYAML(config, 0); err != nil {
			return fmt.Errorf("%s.config: %w", prefix, err)
		}
	}
	if endpoints, ok := fields["endpoints"]; ok {
		if endpoints.Kind != yaml.MappingNode {
			return fmt.Errorf("%s.endpoints must be an object", prefix)
		}
		selectorFields := map[string]*yaml.Node{}
		for i := 0; i < len(endpoints.Content); i += 2 {
			key, value := endpoints.Content[i], endpoints.Content[i+1]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Value != "include" && key.Value != "exclude" {
				return fmt.Errorf("%s.endpoints has unknown field", prefix)
			}
			if _, duplicate := selectorFields[key.Value]; duplicate {
				return fmt.Errorf("%s.endpoints has duplicate field %q", prefix, key.Value)
			}
			selectorFields[key.Value] = value
			if value.Kind != yaml.SequenceNode {
				return fmt.Errorf("%s.endpoints.%s must be an array of strings", prefix, key.Value)
			}
			for _, pattern := range value.Content {
				if pattern.Kind != yaml.ScalarNode || pattern.Tag != "!!str" {
					return fmt.Errorf("%s.endpoints.%s entries must be strings", prefix, key.Value)
				}
			}
		}
	}
	return nil
}

func validateJSONCompatibleYAML(node *yaml.Node, depth int) error {
	if depth > 64 {
		return fmt.Errorf("maximum nesting depth exceeded")
	}
	switch node.Kind {
	case yaml.AliasNode:
		if node.Alias == nil {
			return fmt.Errorf("invalid alias")
		}
		return validateJSONCompatibleYAML(node.Alias, depth+1)
	case yaml.ScalarNode:
		switch node.Tag {
		case "!!str", "!!int", "!!float", "!!bool", "!!null":
			return nil
		default:
			return fmt.Errorf("value with YAML tag %q is not JSON-compatible", node.Tag)
		}
	case yaml.SequenceNode:
		for _, child := range node.Content {
			if err := validateJSONCompatibleYAML(child, depth+1); err != nil {
				return err
			}
		}
		return nil
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				return fmt.Errorf("object keys must be strings")
			}
			if err := validateJSONCompatibleYAML(value, depth+1); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported YAML node")
	}
}

func yamlMappingField(mapping *yaml.Node, name, context string) (*yaml.Node, bool, error) {
	var found *yaml.Node
	for i := 0; i < len(mapping.Content); i += 2 {
		key, value := mapping.Content[i], mapping.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			continue
		}
		if key.Value == name {
			if found != nil {
				return nil, false, fmt.Errorf("policy: %s has duplicate field %q", context, name)
			}
			found = value
		}
	}
	return found, found != nil, nil
}

// Validate performs fail-closed structural checks.
