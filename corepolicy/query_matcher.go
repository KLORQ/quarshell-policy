package policy

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gobwas/glob"
	"gopkg.in/yaml.v3"
)

// QueryMatcher is OpenShell's string glob or {any: [glob, ...]} selector.
// The input-only {glob: string} wrapper canonicalizes to the string form.
// Glob distinguishes an explicit empty string from an empty any-list.
type QueryMatcher struct {
	Glob *string
	Any  []string
}

// Allow constraints require every repeated value to match; deny constraints
// require one matching value for each configured key. All keys must be present.
func matchQuery(rules map[string]QueryMatcher, query map[string][]string, deny bool) bool {
	for key, matcher := range rules {
		values, present := query[key]
		if !present || (!deny && len(values) == 0) {
			return false
		}
		matched := false
		for _, value := range values {
			ok := matcher.Match(value)
			if !deny && !ok {
				return false
			}
			matched = matched || ok
		}
		if deny && len(values) > 0 && !matched {
			return false
		}
	}
	return true
}

func validateQuerySelectors(query map[string]QueryMatcher, protocol string) error {
	if len(query) > 0 && (protocol == ProtocolMCP || protocol == ProtocolJSONRPC) {
		return fmt.Errorf("%s rules must use method, not query", protocol)
	}
	for key, matcher := range query {
		if matcher.Glob == nil && len(matcher.Any) == 0 {
			return fmt.Errorf("query.%s.any must not be empty", key)
		}
	}
	return nil
}

// OpenShell's YAML-to-proto conversion inserts tool as params.name only when
// name is absent. The pinned runtime supports this one MCP parameter selector.
func selectedTool(tool *QueryMatcher, params map[string]QueryMatcher) *QueryMatcher {
	if name, ok := params["name"]; ok {
		return &name
	}
	return tool
}

func matchToolSelector(tool *QueryMatcher, params map[string]QueryMatcher, value string) bool {
	matcher := selectedTool(tool, params)
	return matcher == nil || value != "" && matcher.Match(value)
}

func validateToolSelector(tool *QueryMatcher, params map[string]QueryMatcher, protocol, method string, strict bool) error {
	for key := range params {
		if key != "name" {
			return fmt.Errorf("params.%s: MCP tool argument matching is not supported", key)
		}
	}
	return selectedTool(tool, params).validateTool(protocol, method, strict)
}

func (m *QueryMatcher) validateTool(protocol, method string, strict bool) error {
	if m == nil {
		return nil
	}
	if protocol != ProtocolMCP {
		return fmt.Errorf("tool matcher is only valid for MCP")
	}
	if method != "" && method != "tools/call" {
		return fmt.Errorf("tool matcher requires method tools/call")
	}
	if m.Glob == nil && len(m.Any) == 0 {
		return fmt.Errorf("tool.any must not be empty")
	}
	patterns := m.Any
	if m.Glob != nil {
		patterns = []string{*m.Glob}
	}
	for _, pattern := range patterns {
		if !strict && strings.ContainsAny(pattern, "*?[]{}") {
			return fmt.Errorf("wildcard tool matchers require mcp.strict_tool_names")
		}
	}
	return nil
}

func (m *QueryMatcher) UnmarshalYAML(node *yaml.Node) error {
	*m = QueryMatcher{}
	if node.Kind == yaml.ScalarNode && node.Tag == "!!str" {
		value := node.Value
		m.Glob = &value
		return nil
	}
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("matcher must be a string or an any object")
	}
	seen := false
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Tag != "!!str" || (key.Value != "any" && key.Value != "glob") || seen {
			return fmt.Errorf("matcher has unknown or duplicate field %q", key.Value)
		}
		seen = true
		if key.Value == "glob" {
			if value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
				return fmt.Errorf("matcher.glob must be a string")
			}
			pattern := value.Value
			m.Glob = &pattern
			continue
		}
		if value.Kind != yaml.SequenceNode {
			return fmt.Errorf("matcher.any must be a string list")
		}
		for _, item := range value.Content {
			if item.Kind != yaml.ScalarNode || item.Tag != "!!str" {
				return fmt.Errorf("matcher.any must contain strings")
			}
			m.Any = append(m.Any, item.Value)
		}
	}
	return nil
}

func (m QueryMatcher) MarshalYAML() (any, error) {
	if m.Glob != nil {
		return *m.Glob, nil // OpenShell canonicalizes both glob forms to a string.
	}
	return struct {
		Any []string `yaml:"any,omitempty" json:"any,omitempty"`
	}{m.Any}, nil
}

func (m *QueryMatcher) UnmarshalJSON(data []byte) error {
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return err
	}
	if len(node.Content) != 1 {
		return fmt.Errorf("matcher must be a single value")
	}
	return m.UnmarshalYAML(node.Content[0])
}

func (m QueryMatcher) MarshalJSON() ([]byte, error) {
	value, err := m.MarshalYAML()
	if err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

// Match applies a glob without path separators, as glob.match(pattern, [], value).
// A nil optional matcher imposes no restriction; an empty any-list never matches.
func (m *QueryMatcher) Match(value string) bool {
	if m == nil {
		return true
	}
	patterns := m.Any
	if m.Glob != nil {
		patterns = []string{*m.Glob}
	}
	for _, pattern := range patterns {
		compiled, err := glob.Compile(pattern)
		if err == nil && compiled.Match(value) {
			return true
		}
	}
	return false
}
