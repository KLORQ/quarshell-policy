package policy

import "strings"

// nullForbiddenPatterns mirrors the pinned upstream reject_null_objects list.
var nullForbiddenPatterns = []string{
	"filesystem_policy",
	"landlock",
	"process",
	"network_policies",
	"network_policies.*",
	"network_policies.*.endpoints.*",
	"network_policies.*.binaries.*",
	"network_middlewares",
	"network_middlewares.*",
	"network_middlewares.*.config",
	"network_middlewares.*.endpoints",
	"network_policies.*.endpoints.*.credential_binding",
	"network_policies.*.endpoints.*.json_rpc",
	"network_policies.*.endpoints.*.mcp",
	"network_policies.*.endpoints.*.graphql_persisted_queries",
	"network_policies.*.endpoints.*.graphql_persisted_queries.*",
	"network_policies.*.endpoints.*.rules.*",
	"network_policies.*.endpoints.*.rules.*.allow",
	"network_policies.*.endpoints.*.rules.*.allow.query",
	"network_policies.*.endpoints.*.rules.*.allow.params",
	"network_policies.*.endpoints.*.rules.*.allow.tool",
	"network_policies.*.endpoints.*.deny_rules.*",
	"network_policies.*.endpoints.*.deny_rules.*.query",
	"network_policies.*.endpoints.*.deny_rules.*.params",
	"network_policies.*.endpoints.*.mcp.versions",
	"network_policies.*.endpoints.*.mcp.strict_tool_names",
	"network_policies.*.endpoints.*.mcp.allow_all_known_mcp_methods",
}

func nullForbidden(path []string) bool {
	joined := strings.Join(path, ".")
	for _, pattern := range nullForbiddenPatterns {
		if matchPath(pattern, joined) {
			return true
		}
	}
	return false
}

func matchPath(pattern, path string) bool {
	patternParts := strings.Split(pattern, ".")
	pathParts := strings.Split(path, ".")
	if len(patternParts) != len(pathParts) {
		return false
	}
	for index, part := range patternParts {
		if part != "*" && part != pathParts[index] {
			return false
		}
	}
	return true
}

func arbitraryValuePath(path string) bool {
	for _, segment := range strings.Split(path, ".") {
		if segment == "query" || segment == "params" || segment == "config" {
			return true
		}
	}
	return false
}

func allowedField(path []string, key string) bool {
	if arbitraryValuePath(strings.Join(path, ".")) {
		return true
	}
	parent := strings.Join(path, ".")
	switch parent {
	case "":
		return oneOf(key, "version", "filesystem_policy", "landlock", "process", "network_policies", "network_middlewares")
	case "filesystem_policy":
		return oneOf(key, "include_workdir", "read_only", "read_write")
	case "landlock":
		return oneOf(key, "compatibility")
	case "process":
		return oneOf(key, "run_as_user", "run_as_group")
	case "network_policies", "network_middlewares", "network_policies.*.endpoints.*.graphql_persisted_queries":
		return true
	case "network_policies.*":
		return oneOf(key, "name", "endpoints", "binaries")
	case "network_policies.*.binaries.*":
		return oneOf(key, "path")
	case "network_policies.*.endpoints.*":
		return oneOf(key,
			"host", "path", "port", "ports", "protocol", "tls", "enforcement", "access",
			"rules", "allowed_ips", "deny_rules", "allow_encoded_slash",
			"websocket_credential_rewrite", "request_body_credential_rewrite",
			"allow_uninspected_credentials", "persisted_queries",
			"graphql_persisted_queries", "graphql_max_body_bytes", "credential_signing",
			"signing_service", "signing_region", "credential_binding", "json_rpc", "mcp")
	case "network_policies.*.endpoints.*.credential_binding":
		return oneOf(key, "provider")
	case "network_policies.*.endpoints.*.json_rpc":
		return oneOf(key, "max_body_bytes")
	case "network_policies.*.endpoints.*.mcp":
		return oneOf(key, "versions", "max_body_bytes", "strict_tool_names", "allow_all_known_mcp_methods")
	case "network_policies.*.endpoints.*.graphql_persisted_queries.*":
		return oneOf(key, "operation_type", "operation_name", "fields")
	case "network_policies.*.endpoints.*.rules.*":
		return oneOf(key, "allow")
	case "network_policies.*.endpoints.*.rules.*.allow",
		"network_policies.*.endpoints.*.deny_rules.*":
		return oneOf(key, "method", "path", "command", "query", "operation_type",
			"operation_name", "fields", "tool", "params")
	case "network_middlewares.*":
		return oneOf(key, "name", "middleware", "order", "config", "on_error", "endpoints")
	case "network_middlewares.*.endpoints":
		return oneOf(key, "include", "exclude")
	default:
		return false
	}
}

func oneOf(value string, allowed ...string) bool {
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}

func childPath(path []string, key string) []string {
	parent := strings.Join(path, ".")
	if parent == "network_policies" || parent == "network_middlewares" ||
		parent == "network_policies.*.endpoints.*.graphql_persisted_queries" {
		key = "*"
	}
	result := make([]string, len(path)+1)
	copy(result, path)
	result[len(path)] = key
	return result
}
