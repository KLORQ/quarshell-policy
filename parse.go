package policy

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/KLORQ/quarshell-core/domain"
	"gopkg.in/yaml.v3"
)

const opParse = "policy.parse"

type stats struct {
	nodes       int
	events      int
	scalarBytes int
	aliases     int
	anchors     int
}

// Parse reads one bounded YAML policy document and returns a presence-aware AST.
// It rejects unknown fields, duplicate keys, merge keys, aliases beyond budget,
// explicit nulls where upstream forbids them, and structural budget overflows.
func Parse(reader io.Reader, limits Limits) (*Document, error) {
	body, err := ReadBounded(reader, limits.MaxBytes)
	if err != nil {
		var budget *BudgetError
		if errors.As(err, &budget) {
			return nil, newBudgetError(budget.Kind, budget.Limit, budget.Actual)
		}
		return nil, domain.Wrap(err, opParse, "read policy")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(body))
	var node yaml.Node
	if err := decoder.Decode(&node); err != nil {
		return nil, domain.Wrap(domain.ErrInvalid, opParse, "invalid YAML: "+safeParseError(err))
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err == nil {
		return nil, domain.Invalidf(opParse, "exactly one document is allowed")
	} else if !errors.Is(err, io.EOF) {
		return nil, domain.Wrap(domain.ErrInvalid, opParse, "invalid trailing document")
	}
	if limits.MaxDocuments == 0 {
		limits = DefaultLimits()
	}
	stats := &stats{}
	value, err := convert(&node, nil, stats, limits, map[*yaml.Node]bool{})
	if err != nil {
		return nil, err
	}
	if value.Kind != KindMapping {
		return nil, domain.Invalidf(opParse, "policy root must be a mapping")
	}
	document := &Document{Root: value, Hash: sha256.Sum256(body)}
	version, err := document.Version()
	if err != nil {
		return nil, err
	}
	if version != 1 {
		return nil, domain.Invalidf(opParse, "unsupported policy version %d; expected version 1", version)
	}
	return document, nil
}

func newBudgetError(kind string, limit, actual int) error {
	budget := &BudgetError{Kind: kind, Limit: limit, Actual: actual}
	return &domain.Error{Code: domain.CodeInvalid, Op: opParse, Message: budget.Error(), Err: budget}
}

func countEvents(stats *stats, limits Limits, count int) error {
	stats.events += count
	if stats.events > limits.MaxEvents {
		return newBudgetError("events", limits.MaxEvents, stats.events)
	}
	return nil
}

func convert(node *yaml.Node, path []string, stats *stats, limits Limits, visiting map[*yaml.Node]bool) (*Value, error) {
	if node == nil {
		return nil, domain.Invalidf(opParse, "empty YAML node")
	}
	stats.nodes++
	if stats.nodes > limits.MaxNodes {
		return nil, newBudgetError("nodes", limits.MaxNodes, stats.nodes)
	}
	if len(path) > limits.MaxDepth {
		return nil, newBudgetError("depth", limits.MaxDepth, len(path))
	}
	if node.Anchor != "" {
		stats.anchors++
	}
	switch node.Kind {
	case yaml.DocumentNode:
		if len(node.Content) != 1 {
			return nil, domain.Invalidf(opParse, "invalid YAML document")
		}
		return convert(node.Content[0], path, stats, limits, visiting)
	case yaml.AliasNode:
		stats.aliases++
		if stats.aliases > limits.MaxAliasExpansions {
			return nil, newBudgetError("alias expansions", limits.MaxAliasExpansions, stats.aliases)
		}
		if limits.AliasAnchorRatio > 0 && stats.anchors > 0 &&
			float64(stats.aliases)/float64(stats.anchors) > limits.AliasAnchorRatio {
			return nil, domain.Invalidf(opParse, "alias to anchor ratio exceeds budget")
		}
		if node.Alias == nil {
			return nil, domain.Invalidf(opParse, "alias has no target")
		}
		if visiting[node.Alias] {
			return nil, domain.Invalidf(opParse, "recursive alias")
		}
		visiting[node.Alias] = true
		value, err := convert(node.Alias, path, stats, limits, visiting)
		delete(visiting, node.Alias)
		return value, err
	case yaml.ScalarNode:
		if err := countEvents(stats, limits, 1); err != nil {
			return nil, err
		}
		stats.scalarBytes += len(node.Value)
		if stats.scalarBytes > limits.MaxScalarBytes {
			return nil, newBudgetError("scalar bytes", limits.MaxScalarBytes, stats.scalarBytes)
		}
		kind := KindScalar
		if node.Tag == "!!null" {
			kind = KindNull
		}
		return &Value{Kind: kind, Tag: node.Tag, Scalar: node.Value}, nil
	case yaml.MappingNode:
		if len(node.Content)%2 != 0 {
			return nil, domain.Invalidf(opParse, "invalid mapping")
		}
		keys := len(node.Content) / 2
		if keys > limits.MaxMappingKeys {
			return nil, newBudgetError("mapping keys", limits.MaxMappingKeys, keys)
		}
		if err := countEvents(stats, limits, keys); err != nil {
			return nil, err
		}
		seen := make(map[string]struct{}, keys)
		fields := make([]Entry, 0, keys)
		for index := 0; index < len(node.Content); index += 2 {
			keyNode := node.Content[index]
			valueNode := node.Content[index+1]
			if keyNode.Kind != yaml.ScalarNode {
				return nil, domain.Invalidf(opParse, "mapping keys must be scalars")
			}
			key := keyNode.Value
			if keyNode.Tag == "!!merge" || key == "<<" {
				if limits.MaxMergeKeys == 0 {
					return nil, domain.Invalidf(opParse, "merge keys are not allowed")
				}
			}
			if _, duplicate := seen[key]; duplicate {
				return nil, domain.Invalidf(opParse, "duplicate field %q", key)
			}
			seen[key] = struct{}{}
			if !allowedField(path, key) {
				return nil, domain.Invalidf(opParse, "unknown field %q", joinPath(append(path, key)))
			}
			child := childPath(path, key)
			if valueNode.Kind == yaml.ScalarNode && valueNode.Tag == "!!null" && nullForbidden(child) {
				return nil, domain.Invalidf(opParse, "%s must not be null", joinPath(child))
			}
			converted, err := convert(valueNode, child, stats, limits, visiting)
			if err != nil {
				return nil, err
			}
			if converted.Kind == KindNull && nullForbidden(child) {
				return nil, domain.Invalidf(opParse, "%s must not be null", joinPath(child))
			}
			fields = append(fields, Entry{Key: key, Value: converted})
		}
		return &Value{Kind: KindMapping, Tag: node.Tag, Fields: fields}, nil
	case yaml.SequenceNode:
		if len(node.Content) > limits.MaxSequenceElements {
			return nil, newBudgetError("sequence elements", limits.MaxSequenceElements, len(node.Content))
		}
		if err := countEvents(stats, limits, len(node.Content)); err != nil {
			return nil, err
		}
		itemPath := appendPath(path, "*")
		items := make([]*Value, 0, len(node.Content))
		for _, item := range node.Content {
			converted, err := convert(item, itemPath, stats, limits, visiting)
			if err != nil {
				return nil, err
			}
			if converted.Kind == KindNull && nullForbidden(itemPath) {
				return nil, domain.Invalidf(opParse, "%s must not be null", joinPath(itemPath))
			}
			items = append(items, converted)
		}
		return &Value{Kind: KindSequence, Tag: node.Tag, Items: items}, nil
	default:
		return nil, domain.Invalidf(opParse, "unsupported YAML node kind %d", node.Kind)
	}
}

func appendPath(path []string, value string) []string {
	result := make([]string, len(path)+1)
	copy(result, path)
	result[len(path)] = value
	return result
}

func joinPath(path []string) string {
	result := ""
	for index, part := range path {
		if index > 0 {
			result += "."
		}
		result += part
	}
	return result
}

func safeParseError(err error) string {
	message := err.Error()
	if len(message) > 512 {
		return message[:512]
	}
	return message
}
