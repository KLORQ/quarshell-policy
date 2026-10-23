package policy

import "strings"

type l7Fields struct {
	Method        string
	Path          string
	Command       string
	OperationType string
	OperationName string
	Fields        []string
	Query         map[string]QueryMatcher
	Tool          *QueryMatcher
	Params        *ParameterMatcher
}

func matchL7(fields l7Fields, protocol string, request NetworkRequest) (bool, bool) {
	protocol = strings.ToLower(protocol)
	switch protocol {
	case "", "rest", "http", "https", "websocket":
		return matchRestFields(fields, request)
	case "graphql":
		return matchGraphqlFields(fields, request)
	case "sql":
		return matchSQLFields(fields, request)
	case "json-rpc":
		return matchJSONRPCFields(fields, request)
	case "mcp":
		return matchMCPFields(fields, request)
	default:
		return false, false
	}
}

func matchRestFields(fields l7Fields, request NetworkRequest) (bool, bool) {
	if fields.Command != "" || fields.OperationType != "" || fields.OperationName != "" ||
		len(fields.Fields) > 0 || fields.Tool != nil || fields.Params != nil {
		return false, false
	}
	if fields.Method != "" && !strings.EqualFold(fields.Method, request.Method) {
		return false, true
	}
	if fields.Path != "" && !globMatch(fields.Path, request.Path, '/') {
		return false, true
	}
	if len(fields.Query) > 0 {
		if request.Query == nil {
			return false, true
		}
		for key, matcher := range fields.Query {
			value, exists := request.Query[key]
			if !exists || !matcher.Match(value) {
				return false, true
			}
		}
	}
	return true, true
}

func matchGraphqlFields(fields l7Fields, request NetworkRequest) (bool, bool) {
	if fields.Method != "" || fields.Path != "" || fields.Command != "" ||
		len(fields.Query) > 0 || fields.Tool != nil || fields.Params != nil {
		return false, false
	}
	if fields.OperationType != "" && fields.OperationType != request.OperationType {
		return false, true
	}
	if fields.OperationName != "" && fields.OperationName != request.OperationName {
		return false, true
	}
	if len(fields.Fields) > 0 {
		allowed := make(map[string]struct{}, len(fields.Fields))
		for _, field := range fields.Fields {
			allowed[field] = struct{}{}
		}
		for _, field := range request.Fields {
			if _, ok := allowed[field]; !ok {
				return false, true
			}
		}
		if len(request.Fields) == 0 {
			return false, true
		}
	}
	return true, true
}

func matchSQLFields(fields l7Fields, request NetworkRequest) (bool, bool) {
	if fields.Method != "" || fields.Path != "" || fields.OperationType != "" ||
		fields.OperationName != "" || len(fields.Fields) > 0 ||
		len(fields.Query) > 0 || fields.Tool != nil || fields.Params != nil {
		return false, false
	}
	if fields.Command != "" && fields.Command != request.Command {
		return false, true
	}
	return true, true
}

func matchJSONRPCFields(fields l7Fields, request NetworkRequest) (bool, bool) {
	if fields.Path != "" || fields.Command != "" || fields.OperationType != "" ||
		fields.OperationName != "" || len(fields.Fields) > 0 ||
		len(fields.Query) > 0 || fields.Tool != nil || fields.Params != nil {
		return false, false
	}
	if fields.Method != "" && fields.Method != request.Method {
		return false, true
	}
	return true, true
}

func matchMCPFields(fields l7Fields, request NetworkRequest) (bool, bool) {
	if fields.Path != "" || fields.Command != "" || fields.OperationType != "" ||
		fields.OperationName != "" || len(fields.Fields) > 0 || len(fields.Query) > 0 {
		return false, false
	}
	if fields.Method != "" && fields.Method != request.Method {
		return false, true
	}
	if fields.Tool != nil && !fields.Tool.Match(request.Tool) {
		return false, true
	}
	if fields.Params != nil {
		if fields.Params.Value != nil {
			return false, false
		}
		for key := range fields.Params.Object {
			if key != "name" {
				return false, false
			}
		}
		if matcher, exists := fields.Params.Object["name"]; exists {
			value := ""
			if request.Params != nil {
				if text, ok := request.Params["name"].(string); ok {
					value = text
				}
			}
			if matcher.Value == nil || !matcher.Value.Match(value) {
				return false, true
			}
		}
	}
	return true, true
}
