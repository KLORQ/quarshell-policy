package policy

import "github.com/KLORQ/quarshell-core/domain"

// QueryMatcher is an authored L7 value matcher: one glob or an any-of list.
type QueryMatcher struct {
	Glob string
	Any  []string
}

// Match reports whether value satisfies the matcher.
func (m QueryMatcher) Match(value string) bool {
	if len(m.Any) > 0 {
		for _, pattern := range m.Any {
			if globMatch(pattern, value, 0) {
				return true
			}
		}
		return false
	}
	return globMatch(m.Glob, value, 0)
}

// ParameterMatcher is a nested authored params matcher.
type ParameterMatcher struct {
	Value  *QueryMatcher
	Object map[string]ParameterMatcher
}

func decodeQueryMatchers(value *Value, path string) (map[string]QueryMatcher, error) {
	if value.IsNull() || value.Kind != KindMapping {
		return nil, domain.Invalidf(opDecode, "%s must be a mapping of matchers", path)
	}
	result := make(map[string]QueryMatcher, len(value.Fields))
	for _, entry := range value.Fields {
		matcher, err := decodeQueryMatcher(entry.Value, path+"."+entry.Key)
		if err != nil {
			return nil, err
		}
		result[entry.Key] = matcher
	}
	return result, nil
}

func decodeQueryMatcher(value *Value, path string) (QueryMatcher, error) {
	if value.Kind == KindScalar && (value.Tag == "!!str" || value.Tag == "!!timestamp") {
		return QueryMatcher{Glob: value.Scalar}, nil
	}
	if value.Kind == KindMapping && len(value.Fields) == 1 && value.Fields[0].Key == "any" {
		any, err := decodeStringSequence(value.Fields[0].Value, path+".any")
		if err != nil {
			return QueryMatcher{}, err
		}
		return QueryMatcher{Any: any}, nil
	}
	return QueryMatcher{}, domain.Invalidf(opDecode, "%s must be a string or {any: [...]}", path)
}

func decodeParameterMatcher(value *Value, path string) (ParameterMatcher, error) {
	if value.IsNull() {
		return ParameterMatcher{}, domain.Invalidf(opDecode, "%s must not be null", path)
	}
	if value.Kind == KindScalar && (value.Tag == "!!str" || value.Tag == "!!timestamp") {
		matcher, err := decodeQueryMatcher(value, path)
		if err != nil {
			return ParameterMatcher{}, err
		}
		return ParameterMatcher{Value: &matcher}, nil
	}
	if value.Kind != KindMapping {
		return ParameterMatcher{}, domain.Invalidf(opDecode, "%s must be a matcher or mapping", path)
	}
	if len(value.Fields) == 1 && value.Fields[0].Key == "any" {
		if matcher, err := decodeQueryMatcher(value, path); err == nil {
			return ParameterMatcher{Value: &matcher}, nil
		}
	}
	object := make(map[string]ParameterMatcher, len(value.Fields))
	for _, entry := range value.Fields {
		child, err := decodeParameterMatcher(entry.Value, path+"."+entry.Key)
		if err != nil {
			return ParameterMatcher{}, err
		}
		object[entry.Key] = child
	}
	return ParameterMatcher{Object: object}, nil
}

func decodeStringSequence(value *Value, path string) ([]string, error) {
	if value.Kind != KindSequence {
		return nil, domain.Invalidf(opDecode, "%s must be a sequence of strings", path)
	}
	result := make([]string, 0, len(value.Items))
	for _, item := range value.Items {
		decoded, err := item.StringValue(opDecode, path)
		if err != nil {
			return nil, err
		}
		result = append(result, decoded)
	}
	return result, nil
}
