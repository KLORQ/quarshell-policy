package policy

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Effect is the outcome of one policy evaluation.
type Effect string

const (
	// EffectAllow permits the request.
	EffectAllow Effect = "allow"
	// EffectDeny denies the request.
	EffectDeny Effect = "deny"
	// EffectUnsupported means the policy could not be evaluated faithfully.
	// Callers must fail closed; Unsupported is never an allow.
	EffectUnsupported Effect = "unsupported"
)

// Decision is a typed policy result with a stable reason and matched rule.
type Decision struct {
	Effect   Effect
	Reason   string
	RuleID   string
	Endpoint string
}

// FilesystemAccess is the requested filesystem operation.
type FilesystemAccess string

const (
	AccessRead  FilesystemAccess = "read"
	AccessWrite FilesystemAccess = "write"
	AccessExec  FilesystemAccess = "exec"
)

// FilesystemRequest is one filesystem decision request.
type FilesystemRequest struct {
	Path    string
	Access  FilesystemAccess
	Workdir string
}

// NetworkRequest is one egress decision request.
type NetworkRequest struct {
	Host          string
	Port          uint16
	Protocol      string
	Method        string
	Path          string
	Command       string
	Query         map[string]string
	OperationType string         `yaml:"operation_type" json:"operation_type"`
	OperationName string         `yaml:"operation_name" json:"operation_name"`
	Fields        []string       `yaml:"fields" json:"fields"`
	Tool          string         `yaml:"tool" json:"tool"`
	Params        map[string]any `yaml:"params" json:"params"`
}

// ProcessRequest is one process identity decision request.
type ProcessRequest struct {
	User  string
	Group string
}

// EvaluateFilesystem applies read/write/exec path grants.
func (p *Policy) EvaluateFilesystem(request FilesystemRequest) Decision {
	if p == nil {
		return deny("policy.nil", "no policy snapshot")
	}
	if !p.Filesystem.HasValue() {
		return deny("filesystem.absent", "filesystem policy is absent")
	}
	requested, err := cleanAbsolute(request.Path)
	if err != nil {
		return deny("filesystem.path", err.Error())
	}
	workdir := ""
	if request.Workdir != "" {
		workdir, _ = cleanAbsolute(request.Workdir)
	}
	filesystem := p.Filesystem.Value
	readRoots := append([]string{}, filesystem.ReadOnly...)
	readRoots = append(readRoots, filesystem.ReadWrite...)
	writeRoots := append([]string{}, filesystem.ReadWrite...)
	if filesystem.IncludeWorkdir.OrElse(false) && workdir != "" {
		writeRoots = append(writeRoots, workdir)
		readRoots = append(readRoots, workdir)
	}
	switch request.Access {
	case AccessRead, AccessExec:
		if root, ok := pathUnderAny(requested, readRoots); ok {
			return allow("filesystem.read", root)
		}
		return deny("filesystem.read", "path is not under an allowed read grant")
	case AccessWrite:
		if root, ok := pathUnderAny(requested, writeRoots); ok {
			return allow("filesystem.write", root)
		}
		return deny("filesystem.write", "path is not under an allowed write grant")
	default:
		return unsupported("filesystem.access", "unknown filesystem access kind")
	}
}

// EvaluateProcess applies the authored process identity.
func (p *Policy) EvaluateProcess(request ProcessRequest) Decision {
	if p == nil {
		return deny("policy.nil", "no policy snapshot")
	}
	if !p.Process.HasValue() {
		return allow("process.absent", "no process identity restriction")
	}
	process := p.Process.Value
	if process.RunAsUser.HasValue() && process.RunAsUser.Value != request.User {
		return deny("process.user", "process user does not match policy")
	}
	if process.RunAsGroup.HasValue() && process.RunAsGroup.Value != request.Group {
		return deny("process.group", "process group does not match policy")
	}
	return allow("process.identity", "process identity matches policy")
}

// EvaluateNetwork applies endpoint and L7 allow rules. It never converts an
// unsupported matcher into an allow.
func (p *Policy) EvaluateNetwork(request NetworkRequest) Decision {
	if p == nil {
		return deny("policy.nil", "no policy snapshot")
	}
	if !p.NetworkPolicies.HasValue() || len(p.NetworkPolicies.Value) == 0 {
		return deny("network.absent", "no network policy")
	}
	names := make([]string, 0, len(p.NetworkPolicies.Value))
	for name := range p.NetworkPolicies.Value {
		names = append(names, name)
	}
	sort.Strings(names)
	matched := false
	allowed := false
	unsupported := false
	for _, name := range names {
		rule := p.NetworkPolicies.Value[name]
		for _, endpoint := range rule.Endpoints {
			if !endpointMatches(endpoint, request) {
				continue
			}
			matched = true
			denied, denySupported := denyMatches(endpoint, request)
			if denied {
				return Decision{Effect: EffectDeny, Reason: "L7 deny rule matched", RuleID: name, Endpoint: endpoint.Host}
			}
			if !denySupported {
				unsupported = true
				continue
			}
			ok, allowSupported := allowMatches(endpoint, request)
			if ok {
				allowed = true
			}
			if !allowSupported {
				unsupported = true
			}
		}
	}
	if unsupported {
		return Decision{Effect: EffectUnsupported, Reason: "L7 matcher is not implemented"}
	}
	if allowed {
		return Decision{Effect: EffectAllow, Reason: "endpoint and L7 rule matched"}
	}
	if matched {
		return deny("network.no-rule", "no L7 allow rule matched")
	}
	return deny("network.no-endpoint", "host/port/protocol did not match an endpoint")
}

func endpointMatches(endpoint NetworkEndpoint, request NetworkRequest) bool {
	if endpoint.Host != "" && !globMatch(endpoint.Host, request.Host, '.') {
		return false
	}
	// The pinned runtime gives a non-empty ports list precedence over the
	// single-port compatibility field.
	if len(endpoint.Ports) > 0 {
		found := false
		for _, port := range endpoint.Ports {
			if port == request.Port {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	} else if endpoint.Port.HasValue() {
		if endpoint.Port.Value != request.Port {
			return false
		}
	} else {
		return false
	}
	if endpoint.Protocol != "" && endpoint.Protocol != request.Protocol {
		return false
	}
	return true
}

func denyMatches(endpoint NetworkEndpoint, request NetworkRequest) (bool, bool) {
	supported := true
	for _, rule := range endpoint.DenyRules {
		matched, ruleSupported := matchL7(l7Fields{
			Method: rule.Method, Path: rule.Path, Command: rule.Command,
			OperationType: rule.OperationType, OperationName: rule.OperationName,
			Fields: rule.Fields, Query: rule.Query, Tool: rule.Tool, Params: rule.Params,
		}, endpoint.Protocol, request)
		if !ruleSupported {
			supported = false
			continue
		}
		if matched {
			return true, true
		}
	}
	return false, supported
}

func allowMatches(endpoint NetworkEndpoint, request NetworkRequest) (bool, bool) {
	if len(endpoint.Rules) == 0 {
		if endpoint.Access != "" {
			return accessAllows(endpoint.Access, endpoint.Protocol, request.Method)
		}
		switch strings.ToLower(endpoint.Protocol) {
		case "", "tcp":
			return true, true
		case "mcp":
			allowAll := endpoint.MCP.HasValue() && endpoint.MCP.Value.AllowAllKnownMCPMethods.HasValue() && endpoint.MCP.Value.AllowAllKnownMCPMethods.Value
			return allowAll, true
		case "rest", "http", "https", "websocket", "graphql", "sql", "json-rpc":
			return false, true
		default:
			return false, false
		}
	}
	supported := true
	for _, rule := range endpoint.Rules {
		matched, ruleSupported := matchL7(l7Fields{
			Method: rule.Allow.Method, Path: rule.Allow.Path, Command: rule.Allow.Command,
			OperationType: rule.Allow.OperationType, OperationName: rule.Allow.OperationName,
			Fields: rule.Allow.Fields, Query: rule.Allow.Query, Tool: rule.Allow.Tool, Params: rule.Allow.Params,
		}, endpoint.Protocol, request)
		if !ruleSupported {
			supported = false
			continue
		}
		if matched {
			return true, true
		}
	}
	return false, supported
}

func accessAllows(access, protocol, method string) (bool, bool) {
	websocket := strings.EqualFold(protocol, "websocket")
	switch access {
	case "", "full":
		return true, true
	case "read-only":
		if websocket {
			return strings.EqualFold(method, "GET"), true
		}
		return strings.EqualFold(method, "GET") || strings.EqualFold(method, "HEAD") || strings.EqualFold(method, "OPTIONS"), true
	case "read-write":
		if websocket {
			return strings.EqualFold(method, "GET") || method == "WEBSOCKET_TEXT", true
		}
		switch {
		case strings.EqualFold(method, "GET"), strings.EqualFold(method, "HEAD"), strings.EqualFold(method, "OPTIONS"),
			strings.EqualFold(method, "POST"), strings.EqualFold(method, "PUT"), strings.EqualFold(method, "PATCH"):
			return true, true
		default:
			return false, true
		}
	default:
		return false, false
	}
}

func cleanAbsolute(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", &pathError{"path must be absolute"}
	}
	for _, part := range strings.Split(path, "/") {
		if part == ".." {
			return "", &pathError{"path traversal is not allowed"}
		}
	}
	return filepath.Clean(path), nil
}

type pathError struct{ message string }

func (e *pathError) Error() string { return e.message }

func pathUnderAny(path string, roots []string) (string, bool) {
	for _, root := range roots {
		clean, err := cleanAbsolute(root)
		if err != nil {
			continue
		}
		if path == clean || strings.HasPrefix(path, strings.TrimSuffix(clean, "/")+"/") {
			return clean, true
		}
	}
	return "", false
}

func globMatch(pattern, value string, separator rune) bool {
	var builder strings.Builder
	builder.WriteString("^")
	runes := []rune(pattern)
	for index := 0; index < len(runes); index++ {
		switch runes[index] {
		case '*':
			if index+1 < len(runes) && runes[index+1] == '*' {
				builder.WriteString(".*")
				index++
			} else {
				builder.WriteString("[^")
				builder.WriteString(regexp.QuoteMeta(string(separator)))
				builder.WriteString("]*")
			}
		case '?':
			builder.WriteString("[^")
			builder.WriteString(regexp.QuoteMeta(string(separator)))
			builder.WriteString("]")
		default:
			builder.WriteString(regexp.QuoteMeta(string(runes[index])))
		}
	}
	builder.WriteString("$")
	matched, err := regexp.MatchString(builder.String(), value)
	return err == nil && matched
}

func allow(rule, reason string) Decision {
	return Decision{Effect: EffectAllow, RuleID: rule, Reason: reason}
}

func deny(rule, reason string) Decision {
	return Decision{Effect: EffectDeny, RuleID: rule, Reason: reason}
}

func unsupported(rule, reason string) Decision {
	return Decision{Effect: EffectUnsupported, RuleID: rule, Reason: reason}
}
