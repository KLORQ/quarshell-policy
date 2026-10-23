package policy

import (
	"strconv"

	"github.com/KLORQ/quarshell-core/domain"
)

const opDecode = "policy.decode"

// Policy is the typed authored policy document. Unknown fields and nulls have
// already been rejected by Parse.
type Policy struct {
	Version            uint32
	Filesystem         domain.Field[FilesystemPolicy]
	Landlock           domain.Field[LandlockPolicy]
	Process            domain.Field[ProcessPolicy]
	NetworkPolicies    domain.Field[map[string]NetworkPolicyRule]
	NetworkMiddlewares domain.Field[map[string]NetworkMiddleware]
}

// FilesystemPolicy is the authored filesystem restriction.
type FilesystemPolicy struct {
	IncludeWorkdir domain.Field[bool]
	ReadOnly       []string
	ReadWrite      []string
}

// LandlockPolicy is the authored Landlock compatibility mode.
type LandlockPolicy struct {
	Compatibility domain.Field[string]
}

// ProcessPolicy is the authored process identity.
type ProcessPolicy struct {
	RunAsUser  domain.Field[string]
	RunAsGroup domain.Field[string]
}

// NetworkPolicyRule is one named egress rule.
type NetworkPolicyRule struct {
	Name      domain.Field[string]
	Endpoints []NetworkEndpoint
	Binaries  []NetworkBinary
}

// NetworkEndpoint is one allowed endpoint.
type NetworkEndpoint struct {
	Host                         string
	Path                         string
	Port                         domain.Field[uint16]
	Ports                        []uint16
	Protocol                     string
	TLS                          string
	Enforcement                  string
	Access                       string
	Rules                        []L7Rule
	AllowedIPs                   []string
	DenyRules                    []L7DenyRule
	AllowEncodedSlash            bool
	WebsocketCredentialRewrite   bool
	RequestBodyCredentialRewrite bool
	AllowUninspectedCredentials  bool
	PersistedQueries             string
	GraphqlPersistedQueries      domain.Field[map[string]GraphqlOperation]
	GraphqlMaxBodyBytes          uint32
	CredentialSigning            string
	SigningService               string
	SigningRegion                string
	CredentialBinding            domain.Field[NetworkCredentialBinding]
	JSONRPC                      domain.Field[JSONRPCConfig]
	MCP                          domain.Field[MCPConfig]
	Raw                          *Value
}

// NetworkCredentialBinding binds an endpoint to a provider.
type NetworkCredentialBinding struct {
	Provider string
}

// JSONRPCConfig controls JSON-RPC body limits.
type JSONRPCConfig struct {
	MaxBodyBytes uint32
}

// MCPConfig controls MCP matching and limits.
type MCPConfig struct {
	Versions                domain.Field[[]string]
	MaxBodyBytes            uint32
	StrictToolNames         domain.Field[bool]
	AllowAllKnownMCPMethods domain.Field[bool]
}

// GraphqlOperation is one persisted GraphQL operation.
type GraphqlOperation struct {
	OperationType string
	OperationName string
	Fields        []string
}

// L7Rule is an allow rule.
type L7Rule struct {
	Allow L7Allow
}

// L7Allow is the allow matcher for HTTP, JSON-RPC, MCP, GraphQL, or SQL.
type L7Allow struct {
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

// L7DenyRule is a deny matcher. Deny takes precedence over allow.
type L7DenyRule struct {
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

// NetworkBinary is an executable identity allowed to use a rule.
type NetworkBinary struct {
	Path string
}

// NetworkMiddleware is one ordered middleware.
type NetworkMiddleware struct {
	Name       string
	Middleware string
	Order      int32
	OnError    string
	Config     *Value
	Endpoints  domain.Field[MiddlewareEndpointSelector]
}

// MiddlewareEndpointSelector filters middleware endpoints.
type MiddlewareEndpointSelector struct {
	Include []string
	Exclude []string
}

// Typed returns the typed document representation.
func (d *Document) Typed() (*Policy, error) {
	if d == nil || d.Root == nil {
		return nil, domain.Invalidf(opDecode, "empty policy document")
	}
	version, err := d.Version()
	if err != nil {
		return nil, err
	}
	policy := &Policy{Version: version}
	if err := decodeOptional(d, "filesystem_policy", decodeFilesystem, &policy.Filesystem); err != nil {
		return nil, err
	}
	if err := decodeOptional(d, "landlock", decodeLandlock, &policy.Landlock); err != nil {
		return nil, err
	}
	if err := decodeOptional(d, "process", decodeProcess, &policy.Process); err != nil {
		return nil, err
	}
	if err := decodeOptionalMap(d, "network_policies", decodeNetworkRule, &policy.NetworkPolicies); err != nil {
		return nil, err
	}
	if err := decodeOptionalMap(d, "network_middlewares", decodeMiddleware, &policy.NetworkMiddlewares); err != nil {
		return nil, err
	}
	if err := policy.validateSemantics(); err != nil {
		return nil, err
	}
	return policy, nil
}

func decodeOptional[T any](d *Document, name string, decode func(*Value, string) (T, error), target *domain.Field[T]) error {
	value, ok := d.Field(name)
	if !ok {
		return nil
	}
	if value.IsNull() {
		return domain.Invalidf(opDecode, "%s must not be null", name)
	}
	decoded, err := decode(value, name)
	if err != nil {
		return err
	}
	*target = domain.Some(decoded)
	return nil
}

func decodeOptionalMap[T any](d *Document, name string, decode func(*Value, string) (T, error), target *domain.Field[map[string]T]) error {
	value, ok := d.Field(name)
	if !ok {
		return nil
	}
	if value.IsNull() {
		return domain.Invalidf(opDecode, "%s must not be null", name)
	}
	if value.Kind != KindMapping {
		return domain.Invalidf(opDecode, "%s must be a mapping", name)
	}
	result := make(map[string]T, len(value.Fields))
	for _, entry := range value.Fields {
		decoded, err := decode(entry.Value, name+"."+entry.Key)
		if err != nil {
			return err
		}
		result[entry.Key] = decoded
	}
	*target = domain.Some(result)
	return nil
}

func decodeFilesystem(value *Value, path string) (FilesystemPolicy, error) {
	var result FilesystemPolicy
	if value.Kind != KindMapping {
		return result, domain.Invalidf(opDecode, "%s must be a mapping", path)
	}
	var err error
	result.IncludeWorkdir, err = optionalBool(value, "include_workdir", path)
	if err != nil {
		return result, err
	}
	result.ReadOnly, err = optionalStringSliceValue(value, "read_only", path)
	if err != nil {
		return result, err
	}
	result.ReadWrite, err = optionalStringSliceValue(value, "read_write", path)
	if err != nil {
		return result, err
	}
	return result, nil
}

func decodeLandlock(value *Value, path string) (LandlockPolicy, error) {
	var result LandlockPolicy
	if value.Kind != KindMapping {
		return result, domain.Invalidf(opDecode, "%s must be a mapping", path)
	}
	compatibility, err := optionalString(value, "compatibility", path)
	if err != nil {
		return result, err
	}
	if compatibility.HasValue() {
		switch compatibility.Value {
		case "", "best_effort", "hard_requirement":
		default:
			return result, domain.Invalidf(opDecode, "landlock.compatibility must be best_effort or hard_requirement")
		}
	}
	result.Compatibility = compatibility
	return result, nil
}

func decodeProcess(value *Value, path string) (ProcessPolicy, error) {
	var result ProcessPolicy
	if value.Kind != KindMapping {
		return result, domain.Invalidf(opDecode, "%s must be a mapping", path)
	}
	var err error
	result.RunAsUser, err = optionalString(value, "run_as_user", path)
	if err != nil {
		return result, err
	}
	result.RunAsGroup, err = optionalString(value, "run_as_group", path)
	if err != nil {
		return result, err
	}
	return result, nil
}

func decodeNetworkRule(value *Value, path string) (NetworkPolicyRule, error) {
	var result NetworkPolicyRule
	if value.Kind != KindMapping {
		return result, domain.Invalidf(opDecode, "%s must be a mapping", path)
	}
	var err error
	result.Name, err = optionalString(value, "name", path)
	if err != nil {
		return result, err
	}
	endpoints, ok := value.Field("endpoints")
	if ok {
		if endpoints.Kind != KindSequence {
			return result, domain.Invalidf(opDecode, "%s.endpoints must be a sequence", path)
		}
		for index, item := range endpoints.Items {
			decoded, err := decodeEndpoint(item, path+".endpoints."+indexString(index))
			if err != nil {
				return result, err
			}
			result.Endpoints = append(result.Endpoints, decoded)
		}
	}
	binaries, ok := value.Field("binaries")
	if ok {
		if binaries.Kind != KindSequence {
			return result, domain.Invalidf(opDecode, "%s.binaries must be a sequence", path)
		}
		for index, item := range binaries.Items {
			if item.Kind != KindMapping {
				return result, domain.Invalidf(opDecode, "%s.binaries.%s must be a mapping", path, indexString(index))
			}
			binaryPath, err := requiredString(item, "path", path+".binaries."+indexString(index))
			if err != nil {
				return result, err
			}
			result.Binaries = append(result.Binaries, NetworkBinary{Path: binaryPath})
		}
	}
	return result, nil
}

func decodeEndpoint(value *Value, path string) (NetworkEndpoint, error) {
	var result NetworkEndpoint
	if value.Kind != KindMapping {
		return result, domain.Invalidf(opDecode, "%s must be a mapping", path)
	}
	var err error
	result.Host, err = optionalStringValue(value, "host", path)
	if err != nil {
		return result, err
	}
	result.Path, err = optionalStringValue(value, "path", path)
	if err != nil {
		return result, err
	}
	result.Protocol, err = optionalStringValue(value, "protocol", path)
	if err != nil {
		return result, err
	}
	result.TLS, err = optionalStringValue(value, "tls", path)
	if err != nil {
		return result, err
	}
	result.Enforcement, err = optionalStringValue(value, "enforcement", path)
	if err != nil {
		return result, err
	}
	result.Access, err = optionalStringValue(value, "access", path)
	if err != nil {
		return result, err
	}
	result.PersistedQueries, err = optionalStringValue(value, "persisted_queries", path)
	if err != nil {
		return result, err
	}
	result.CredentialSigning, err = optionalStringValue(value, "credential_signing", path)
	if err != nil {
		return result, err
	}
	result.SigningService, err = optionalStringValue(value, "signing_service", path)
	if err != nil {
		return result, err
	}
	result.SigningRegion, err = optionalStringValue(value, "signing_region", path)
	if err != nil {
		return result, err
	}
	if port, ok := value.Field("port"); ok {
		parsed, err := port.Uint16Value(opDecode, path+".port")
		if err != nil {
			return result, err
		}
		result.Port = domain.Some(parsed)
	}
	if ports, ok := value.Field("ports"); ok {
		if ports.Kind != KindSequence {
			return result, domain.Invalidf(opDecode, "%s.ports must be a sequence", path)
		}
		for _, item := range ports.Items {
			parsed, err := item.Uint16Value(opDecode, path+".ports")
			if err != nil {
				return result, err
			}
			result.Ports = append(result.Ports, parsed)
		}
	}
	result.AllowedIPs, err = optionalStringSliceValue(value, "allowed_ips", path)
	if err != nil {
		return result, err
	}
	result.AllowEncodedSlash, err = optionalBoolValue(value, "allow_encoded_slash", path)
	if err != nil {
		return result, err
	}
	result.WebsocketCredentialRewrite, err = optionalBoolValue(value, "websocket_credential_rewrite", path)
	if err != nil {
		return result, err
	}
	result.RequestBodyCredentialRewrite, err = optionalBoolValue(value, "request_body_credential_rewrite", path)
	if err != nil {
		return result, err
	}
	result.AllowUninspectedCredentials, err = optionalBoolValue(value, "allow_uninspected_credentials", path)
	if err != nil {
		return result, err
	}
	if maxBody, ok := value.Field("graphql_max_body_bytes"); ok {
		parsed, err := maxBody.Uint32Value(opDecode, path+".graphql_max_body_bytes")
		if err != nil {
			return result, err
		}
		result.GraphqlMaxBodyBytes = parsed
	}
	if rules, ok := value.Field("rules"); ok {
		if rules.Kind != KindSequence {
			return result, domain.Invalidf(opDecode, "%s.rules must be a sequence", path)
		}
		for index, item := range rules.Items {
			decoded, err := decodeAllowRule(item, path+".rules."+indexString(index))
			if err != nil {
				return result, err
			}
			result.Rules = append(result.Rules, decoded)
		}
	}
	if denyRules, ok := value.Field("deny_rules"); ok {
		if denyRules.Kind != KindSequence {
			return result, domain.Invalidf(opDecode, "%s.deny_rules must be a sequence", path)
		}
		for index, item := range denyRules.Items {
			decoded, err := decodeDenyRule(item, path+".deny_rules."+indexString(index))
			if err != nil {
				return result, err
			}
			result.DenyRules = append(result.DenyRules, decoded)
		}
	}
	if binding, ok := value.Field("credential_binding"); ok {
		decoded, err := decodeBinding(binding, path+".credential_binding")
		if err != nil {
			return result, err
		}
		result.CredentialBinding = domain.Some(decoded)
	}
	if jsonRPC, ok := value.Field("json_rpc"); ok {
		decoded, err := decodeJSONRPC(jsonRPC, path+".json_rpc")
		if err != nil {
			return result, err
		}
		result.JSONRPC = domain.Some(decoded)
	}
	if mcp, ok := value.Field("mcp"); ok {
		decoded, err := decodeMCP(mcp, path+".mcp")
		if err != nil {
			return result, err
		}
		result.MCP = domain.Some(decoded)
	}
	if queries, ok := value.Field("graphql_persisted_queries"); ok {
		if queries.Kind != KindMapping {
			return result, domain.Invalidf(opDecode, "%s.graphql_persisted_queries must be a mapping", path)
		}
		decodedMap := make(map[string]GraphqlOperation, len(queries.Fields))
		for _, entry := range queries.Fields {
			operation, err := decodeGraphqlOperation(entry.Value, path+".graphql_persisted_queries."+entry.Key)
			if err != nil {
				return result, err
			}
			decodedMap[entry.Key] = operation
		}
		result.GraphqlPersistedQueries = domain.Some(decodedMap)
	}
	result.Raw = value
	return result, nil
}

func decodeAllowRule(value *Value, path string) (L7Rule, error) {
	var result L7Rule
	if value.Kind != KindMapping {
		return result, domain.Invalidf(opDecode, "%s must be a mapping", path)
	}
	allow, ok := value.Field("allow")
	if !ok || allow.Kind != KindMapping {
		return result, domain.Invalidf(opDecode, "%s.allow must be a mapping", path)
	}
	decoded, err := decodeAllow(allow, path+".allow")
	if err != nil {
		return result, err
	}
	result.Allow = decoded
	return result, nil
}

func decodeAllow(value *Value, path string) (L7Allow, error) {
	var result L7Allow
	var err error
	if result.Method, err = optionalStringValue(value, "method", path); err != nil {
		return result, err
	}
	if result.Path, err = optionalStringValue(value, "path", path); err != nil {
		return result, err
	}
	if result.Command, err = optionalStringValue(value, "command", path); err != nil {
		return result, err
	}
	if result.OperationType, err = optionalStringValue(value, "operation_type", path); err != nil {
		return result, err
	}
	if result.OperationName, err = optionalStringValue(value, "operation_name", path); err != nil {
		return result, err
	}
	if result.Fields, err = optionalStringSliceValue(value, "fields", path); err != nil {
		return result, err
	}
	if field, ok := value.Field("query"); ok {
		result.Query, err = decodeQueryMatchers(field, path+".query")
		if err != nil {
			return result, err
		}
	}
	if field, ok := value.Field("tool"); ok {
		matcher, matcherErr := decodeQueryMatcher(field, path+".tool")
		if matcherErr != nil {
			return result, matcherErr
		}
		result.Tool = &matcher
	}
	if field, ok := value.Field("params"); ok {
		matcher, matcherErr := decodeParameterMatcher(field, path+".params")
		if matcherErr != nil {
			return result, matcherErr
		}
		result.Params = &matcher
	}
	return result, nil
}

func decodeDenyRule(value *Value, path string) (L7DenyRule, error) {
	var result L7DenyRule
	if value.Kind != KindMapping {
		return result, domain.Invalidf(opDecode, "%s must be a mapping", path)
	}
	var err error
	if result.Method, err = optionalStringValue(value, "method", path); err != nil {
		return result, err
	}
	if result.Path, err = optionalStringValue(value, "path", path); err != nil {
		return result, err
	}
	if result.Command, err = optionalStringValue(value, "command", path); err != nil {
		return result, err
	}
	if result.OperationType, err = optionalStringValue(value, "operation_type", path); err != nil {
		return result, err
	}
	if result.OperationName, err = optionalStringValue(value, "operation_name", path); err != nil {
		return result, err
	}
	if result.Fields, err = optionalStringSliceValue(value, "fields", path); err != nil {
		return result, err
	}
	if field, ok := value.Field("query"); ok {
		result.Query, err = decodeQueryMatchers(field, path+".query")
		if err != nil {
			return result, err
		}
	}
	if field, ok := value.Field("tool"); ok {
		matcher, matcherErr := decodeQueryMatcher(field, path+".tool")
		if matcherErr != nil {
			return result, matcherErr
		}
		result.Tool = &matcher
	}
	if field, ok := value.Field("params"); ok {
		matcher, matcherErr := decodeParameterMatcher(field, path+".params")
		if matcherErr != nil {
			return result, matcherErr
		}
		result.Params = &matcher
	}
	return result, nil
}

func decodeBinding(value *Value, path string) (NetworkCredentialBinding, error) {
	var result NetworkCredentialBinding
	if value.Kind != KindMapping {
		return result, domain.Invalidf(opDecode, "%s must be a mapping", path)
	}
	provider, err := requiredString(value, "provider", path)
	if err != nil {
		return result, err
	}
	result.Provider = provider
	return result, nil
}

func decodeJSONRPC(value *Value, path string) (JSONRPCConfig, error) {
	var result JSONRPCConfig
	if value.Kind != KindMapping {
		return result, domain.Invalidf(opDecode, "%s must be a mapping", path)
	}
	if maxBody, ok := value.Field("max_body_bytes"); ok {
		parsed, err := maxBody.Uint32Value(opDecode, path+".max_body_bytes")
		if err != nil {
			return result, err
		}
		result.MaxBodyBytes = parsed
	}
	return result, nil
}

func decodeMCP(value *Value, path string) (MCPConfig, error) {
	var result MCPConfig
	if value.Kind != KindMapping {
		return result, domain.Invalidf(opDecode, "%s must be a mapping", path)
	}
	var err error
	result.Versions, err = optionalStringSlice(value, "versions", path)
	if err != nil {
		return result, err
	}
	result.StrictToolNames, err = optionalBool(value, "strict_tool_names", path)
	if err != nil {
		return result, err
	}
	result.AllowAllKnownMCPMethods, err = optionalBool(value, "allow_all_known_mcp_methods", path)
	if err != nil {
		return result, err
	}
	if maxBody, ok := value.Field("max_body_bytes"); ok {
		parsed, err := maxBody.Uint32Value(opDecode, path+".max_body_bytes")
		if err != nil {
			return result, err
		}
		result.MaxBodyBytes = parsed
	}
	return result, nil
}

func decodeGraphqlOperation(value *Value, path string) (GraphqlOperation, error) {
	var result GraphqlOperation
	if value.Kind != KindMapping {
		return result, domain.Invalidf(opDecode, "%s must be a mapping", path)
	}
	var err error
	result.OperationType, err = optionalStringValue(value, "operation_type", path)
	if err != nil {
		return result, err
	}
	result.OperationName, err = optionalStringValue(value, "operation_name", path)
	if err != nil {
		return result, err
	}
	result.Fields, err = optionalStringSliceValue(value, "fields", path)
	return result, err
}

func decodeMiddleware(value *Value, path string) (NetworkMiddleware, error) {
	var result NetworkMiddleware
	if value.Kind != KindMapping {
		return result, domain.Invalidf(opDecode, "%s must be a mapping", path)
	}
	var err error
	if result.Name, err = optionalStringValue(value, "name", path); err != nil {
		return result, err
	}
	if result.Middleware, err = requiredString(value, "middleware", path); err != nil {
		return result, err
	}
	if result.OnError, err = optionalStringValue(value, "on_error", path); err != nil {
		return result, err
	}
	if order, ok := value.Field("order"); ok {
		parsed, err := order.Int32Value(opDecode, path+".order")
		if err != nil {
			return result, err
		}
		result.Order = parsed
	}
	result.Config, _ = value.Field("config")
	if endpoints, ok := value.Field("endpoints"); ok {
		selector, err := decodeMiddlewareEndpoints(endpoints, path+".endpoints")
		if err != nil {
			return result, err
		}
		result.Endpoints = domain.Some(selector)
	}
	return result, nil
}

func decodeMiddlewareEndpoints(value *Value, path string) (MiddlewareEndpointSelector, error) {
	var result MiddlewareEndpointSelector
	if value.Kind != KindMapping {
		return result, domain.Invalidf(opDecode, "%s must be a mapping", path)
	}
	var err error
	if result.Include, err = optionalStringSliceValue(value, "include", path); err != nil {
		return result, err
	}
	if result.Exclude, err = optionalStringSliceValue(value, "exclude", path); err != nil {
		return result, err
	}
	return result, nil
}

func optionalString(value *Value, name, path string) (domain.Field[string], error) {
	field, ok := value.Field(name)
	if !ok {
		return domain.Absent[string](), nil
	}
	if field.IsNull() {
		return domain.Field[string]{}, domain.Invalidf(opDecode, "%s.%s must not be null", path, name)
	}
	decoded, err := field.StringValue(opDecode, path+"."+name)
	if err != nil {
		return domain.Field[string]{}, err
	}
	return domain.Some(decoded), nil
}

func optionalStringValue(value *Value, name, path string) (string, error) {
	field, ok := value.Field(name)
	if !ok {
		return "", nil
	}
	if field.IsNull() {
		return "", domain.Invalidf(opDecode, "%s.%s must not be null", path, name)
	}
	return field.StringValue(opDecode, path+"."+name)
}

func requiredString(value *Value, name, path string) (string, error) {
	field, ok := value.Field(name)
	if !ok || field.IsNull() {
		return "", domain.Invalidf(opDecode, "%s.%s is required", path, name)
	}
	return field.StringValue(opDecode, path+"."+name)
}

func optionalBool(value *Value, name, path string) (domain.Field[bool], error) {
	field, ok := value.Field(name)
	if !ok {
		return domain.Absent[bool](), nil
	}
	if field.IsNull() {
		return domain.Field[bool]{}, domain.Invalidf(opDecode, "%s.%s must not be null", path, name)
	}
	decoded, err := field.BoolValue(opDecode, path+"."+name)
	if err != nil {
		return domain.Field[bool]{}, err
	}
	return domain.Some(decoded), nil
}

func optionalBoolValue(value *Value, name, path string) (bool, error) {
	field, ok := value.Field(name)
	if !ok {
		return false, nil
	}
	if field.IsNull() {
		return false, domain.Invalidf(opDecode, "%s.%s must not be null", path, name)
	}
	return field.BoolValue(opDecode, path+"."+name)
}

func optionalStringSlice(value *Value, name, path string) (domain.Field[[]string], error) {
	field, ok := value.Field(name)
	if !ok {
		return domain.Absent[[]string](), nil
	}
	if field.IsNull() {
		return domain.Field[[]string]{}, domain.Invalidf(opDecode, "%s.%s must not be null", path, name)
	}
	decoded, err := optionalStringSliceValue(value, name, path)
	if err != nil {
		return domain.Field[[]string]{}, err
	}
	return domain.Some(decoded), nil
}

func optionalStringSliceValue(value *Value, name, path string) ([]string, error) {
	field, ok := value.Field(name)
	if !ok {
		return nil, nil
	}
	if field.IsNull() {
		return nil, domain.Invalidf(opDecode, "%s.%s must not be null", path, name)
	}
	if field.Kind != KindSequence {
		return nil, domain.Invalidf(opDecode, "%s.%s must be a sequence", path, name)
	}
	result := make([]string, 0, len(field.Items))
	for _, item := range field.Items {
		decoded, err := item.StringValue(opDecode, path+"."+name)
		if err != nil {
			return nil, err
		}
		result = append(result, decoded)
	}
	return result, nil
}

func indexString(index int) string {
	return strconv.Itoa(index)
}
