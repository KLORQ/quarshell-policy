package policy

import (
	"gopkg.in/yaml.v3"
)

// Document is the canonical sandbox policy (OpenShell YAML naming).
type Document struct {
	Version            uint32                   `yaml:"version" json:"version"`
	FilesystemPolicy   *FilesystemPolicy        `yaml:"filesystem_policy,omitempty" json:"filesystem_policy,omitempty"`
	Landlock           *Landlock                `yaml:"landlock,omitempty" json:"landlock,omitempty"`
	Process            *Process                 `yaml:"process,omitempty" json:"process,omitempty"`
	NetworkPolicies    map[string]NetworkPolicy `yaml:"network_policies,omitempty" json:"network_policies,omitempty"`
	NetworkMiddlewares map[string]yaml.Node     `yaml:"network_middlewares,omitempty" json:"network_middlewares,omitempty"`
	Inference          *Inference               `yaml:"inference,omitempty" json:"inference,omitempty"`
	Display            *Display                 `yaml:"display,omitempty" json:"display,omitempty"`
	Credentials        *Credentials             `yaml:"credentials,omitempty" json:"credentials,omitempty"`
	// Binaries is a top-level TOFU path allowlist (globs). Empty = no global binary gate.
	Binaries []string `yaml:"binaries,omitempty" json:"binaries,omitempty"`
}

type FilesystemPolicy struct {
	IncludeWorkdir bool `yaml:"include_workdir" json:"include_workdir"`
	// IncludeWorkdirSet preserves an explicit false while omitted fields use
	// OpenShell's default of true.
	IncludeWorkdirSet bool     `yaml:"-" json:"-"`
	ReadOnly          []string `yaml:"read_only,omitempty" json:"read_only,omitempty"`
	ReadWrite         []string `yaml:"read_write,omitempty" json:"read_write,omitempty"`
}

type Landlock struct {
	// Compatibility: best_effort | hard_requirement.
	Compatibility string `yaml:"compatibility,omitempty" json:"compatibility,omitempty"`
}

type Process struct {
	RunAsUser  string `yaml:"run_as_user,omitempty" json:"run_as_user,omitempty"`
	RunAsGroup string `yaml:"run_as_group,omitempty" json:"run_as_group,omitempty"`
}

type NetworkPolicy struct {
	Name      string          `yaml:"name,omitempty" json:"name,omitempty"`
	Endpoints []AllowRule     `yaml:"endpoints,omitempty" json:"endpoints,omitempty"`
	Binaries  []NetworkBinary `yaml:"binaries,omitempty" json:"binaries,omitempty"`
}

// NetworkBinary restricts which binaries may use the rule (empty = any).

// NetworkBinary restricts which binaries may use the rule (empty = any).
type NetworkBinary struct {
	Path    string `yaml:"path" json:"path"`
	Harness bool   `yaml:"harness,omitempty" json:"-"` // deprecated by OpenShell; accepted and ignored
}

// AllowRule is one egress endpoint (L4 + optional L7). Used under
// network_policies.*.endpoints and as the flattened engine view.

// AllowRule is one egress endpoint (L4 + optional L7). Used under
// network_policies.*.endpoints and as the flattened engine view.
type AllowRule struct {
	ID       string   `yaml:"id,omitempty" json:"id,omitempty"`
	Host     string   `yaml:"host,omitempty" json:"host,omitempty"`
	Port     int      `yaml:"port,omitempty" json:"port,omitempty"`
	Ports    []int    `yaml:"ports,omitempty" json:"ports,omitempty"`
	Binaries []string `yaml:"binaries,omitempty" json:"binaries,omitempty"`

	// L7. Empty Protocol = L4 CONNECT tunnel only.
	Protocol   string       `yaml:"protocol,omitempty" json:"protocol,omitempty"` // rest | websocket | graphql | json-rpc | mcp
	TLS        string       `yaml:"tls,omitempty" json:"tls,omitempty"`           // skip disables TLS inspection; terminate/passthrough are deprecated Auto aliases
	Access     string       `yaml:"access,omitempty" json:"access,omitempty"`     // read-only | read-write | full
	Path       string       `yaml:"path,omitempty" json:"path,omitempty"`
	Rules      []L7Rule     `yaml:"rules,omitempty" json:"rules,omitempty"`
	DenyRules  []L7DenyRule `yaml:"deny_rules,omitempty" json:"deny_rules,omitempty"`
	AllowedIPs []string     `yaml:"allowed_ips,omitempty" json:"allowed_ips,omitempty"`
	// Enforcement is enforce (default) or audit.
	Enforcement string `yaml:"enforcement,omitempty" json:"enforcement,omitempty"`
	// CredentialKeys binds quarshell:resolve:env:KEY rewrite to this endpoint.
	CredentialKeys               []string                       `yaml:"credential_keys,omitempty" json:"credential_keys,omitempty"`
	CredentialSigning            string                         `yaml:"credential_signing,omitempty" json:"credential_signing,omitempty"`
	SigningService               string                         `yaml:"signing_service,omitempty" json:"signing_service,omitempty"`
	SigningRegion                string                         `yaml:"signing_region,omitempty" json:"signing_region,omitempty"`
	WebsocketCredentialRewrite   bool                           `yaml:"websocket_credential_rewrite,omitempty" json:"websocket_credential_rewrite,omitempty"`
	RequestBodyCredentialRewrite bool                           `yaml:"request_body_credential_rewrite,omitempty" json:"request_body_credential_rewrite,omitempty"`
	PersistedQueries             string                         `yaml:"persisted_queries,omitempty" json:"persisted_queries,omitempty"`
	GraphQLPersistedQueries      map[string]GraphQLOperationDef `yaml:"graphql_persisted_queries,omitempty" json:"graphql_persisted_queries,omitempty"`
	GraphQLMaxBodyBytes          *uint32                        `yaml:"graphql_max_body_bytes,omitempty" json:"graphql_max_body_bytes,omitempty"`
	AllowEncodedSlash            bool                           `yaml:"allow_encoded_slash,omitempty" json:"allow_encoded_slash,omitempty"`
	AllowUninspectedCredentials  bool                           `yaml:"allow_uninspected_credentials,omitempty" json:"allow_uninspected_credentials,omitempty"`
	CredentialBinding            *CredentialBinding             `yaml:"credential_binding,omitempty" json:"credential_binding,omitempty"`
	JSONRPC                      *JSONRPCConfig                 `yaml:"json_rpc,omitempty" json:"json_rpc,omitempty"`
	MCP                          *MCPConfig                     `yaml:"mcp,omitempty" json:"mcp,omitempty"`

	// networkPolicyKey/name preserve the source map identity across flattening
	// and SetNetworkAllows updates. They are not part of the serialized schema.
	networkPolicyKey  string
	networkPolicyName string
}

// CredentialBinding names an attached, endpointless provider instance whose
// credentials may be used only for this endpoint.

// CredentialBinding names an attached, endpointless provider instance whose
// credentials may be used only for this endpoint.
type CredentialBinding struct {
	Provider string `yaml:"provider" json:"provider"`
}

// GraphQLOperationDef is one trusted persisted GraphQL operation.

// GraphQLOperationDef is one trusted persisted GraphQL operation.
type GraphQLOperationDef struct {
	OperationType string   `yaml:"operation_type,omitempty" json:"operation_type,omitempty"`
	OperationName string   `yaml:"operation_name,omitempty" json:"operation_name,omitempty"`
	Fields        []string `yaml:"fields,omitempty" json:"fields,omitempty"`
}

// GraphQLOperation is the parsed policy-visible request shape.

// GraphQLOperation is the parsed policy-visible request shape.
type GraphQLOperation struct {
	OperationType      string
	OperationName      string
	Fields             []string
	Persisted          bool
	PersistedQueryHash string
	PersistedQueryID   string
}

// MCPConfig mirrors OpenShell's endpoint-level MCP options.

// MCPConfig mirrors OpenShell's endpoint-level MCP options.
type MCPConfig struct {
	Versions                []string `yaml:"versions,omitempty" json:"versions,omitempty"`
	MaxBodyBytes            uint32   `yaml:"max_body_bytes,omitempty" json:"max_body_bytes,omitempty"`
	StrictToolNames         *bool    `yaml:"strict_tool_names,omitempty" json:"strict_tool_names,omitempty"`
	AllowAllKnownMCPMethods *bool    `yaml:"allow_all_known_mcp_methods,omitempty" json:"allow_all_known_mcp_methods,omitempty"`
}

// JSONRPCConfig mirrors the OpenShell generic JSON-RPC endpoint options.

// JSONRPCConfig mirrors the OpenShell generic JSON-RPC endpoint options.
type JSONRPCConfig struct {
	MaxBodyBytes *uint32 `yaml:"max_body_bytes,omitempty" json:"max_body_bytes,omitempty"`
}

// Display is the noVNC surface (quarshell product extension).

// Display is the noVNC surface (quarshell product extension).
type Display struct {
	Mode    string `yaml:"mode,omitempty" json:"mode,omitempty"` // none | novnc
	Publish string `yaml:"publish,omitempty" json:"publish,omitempty"`
	Port    int    `yaml:"port,omitempty" json:"port,omitempty"`
	Auth    string `yaml:"auth,omitempty" json:"auth,omitempty"`
	Browser string `yaml:"browser,omitempty" json:"browser,omitempty"`
}

// Credentials controls host-side env injection (quarshell product extension).

// Credentials controls host-side env injection (quarshell product extension).
type Credentials struct {
	EnvAllow    []string `yaml:"env_allow,omitempty" json:"env_allow,omitempty"`
	WriteToDisk bool     `yaml:"write_to_disk,omitempty" json:"write_to_disk,omitempty"`
}

// Load reads and parses a policy YAML file.
