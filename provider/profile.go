package provider

import "github.com/KLORQ/quarshell-policy/corepolicy"

// Profile is a reusable provider type (catalog entry).
type Profile struct {
	ID              string            `yaml:"id" json:"id"`
	ResourceVersion uint64            `yaml:"resource_version,omitempty" json:"resource_version,omitempty"`
	Annotations     map[string]string `yaml:"annotations,omitempty" json:"annotations,omitempty"`
	// Source and Scope are server-set OpenShell metadata. They are retained for
	// config round-trips; catalog provenance and visibility come from the gateway.
	Source           string             `yaml:"source,omitempty" json:"source,omitempty"`
	Scope            string             `yaml:"scope,omitempty" json:"scope,omitempty"`
	DisplayName      string             `yaml:"display_name,omitempty" json:"display_name,omitempty"`
	Description      string             `yaml:"description,omitempty" json:"description,omitempty"`
	Category         string             `yaml:"category,omitempty" json:"category,omitempty"`
	InferenceCapable bool               `yaml:"inference_capable,omitempty" json:"inference_capable,omitempty"`
	Discovery        Discovery          `yaml:"discovery,omitempty" json:"discovery"`
	Endpoints        []policy.AllowRule `yaml:"endpoints,omitempty" json:"endpoints,omitempty"`
	Binaries         []string           `yaml:"binaries,omitempty" json:"binaries,omitempty"`
	Credentials      []Credential       `yaml:"credentials,omitempty" json:"credentials,omitempty"`
}

// Discovery selects credentials considered by --from-existing. An empty list
// disables credential environment discovery, as in the pinned OpenShell contract.
type Discovery struct {
	Credentials []string `yaml:"credentials,omitempty" json:"credentials,omitempty"`
}

// Credential declares env keys for an attached instance.
// Values live in the gateway secret store; guests see quarshell:resolve:env:KEY
// placeholders unless InjectEnv is false (sidecar-only — Cursor OAuth path).
type Credential struct {
	Name              string             `yaml:"name" json:"name"`
	Description       string             `yaml:"description,omitempty" json:"description,omitempty"`
	EnvVars           []string           `yaml:"env_vars,omitempty" json:"env_vars,omitempty"`
	AuthStyle         string             `yaml:"auth_style,omitempty" json:"auth_style,omitempty"`
	Header            string             `yaml:"header_name,omitempty" json:"header_name,omitempty"`
	QueryParam        string             `yaml:"query_param,omitempty" json:"query_param,omitempty"`
	PathTemplate      string             `yaml:"path_template,omitempty" json:"path_template,omitempty"`
	Required          bool               `yaml:"required,omitempty" json:"required,omitempty"`
	Secret            bool               `yaml:"secret,omitempty" json:"secret,omitempty"`
	StablePlaceholder bool               `yaml:"stable_placeholder,omitempty" json:"stable_placeholder,omitempty"`
	Refresh           *CredentialRefresh `yaml:"refresh,omitempty" json:"refresh,omitempty"`
	TokenGrant        *TokenGrant        `yaml:"token_grant,omitempty" json:"token_grant,omitempty"`
	// InjectEnv controls guest env placeholders. nil/omitted → true.
	// Set false for agents that client-validate API keys (e.g. Cursor Agent).
	InjectEnv *bool `yaml:"inject_env,omitempty" json:"inject_env,omitempty"`
}

// CredentialRefresh describes gateway-side rotation inputs. The gateway may
// reject strategies it cannot execute, but import/export retains the contract.
type CredentialRefresh struct {
	Strategy             string            `yaml:"strategy" json:"strategy"`
	TokenURL             string            `yaml:"token_url,omitempty" json:"token_url,omitempty"`
	TokenURI             string            `yaml:"token_uri,omitempty" json:"token_uri,omitempty"`
	Scopes               []string          `yaml:"scopes,omitempty" json:"scopes,omitempty"`
	RefreshBefore        string            `yaml:"refresh_before,omitempty" json:"refresh_before,omitempty"`
	MaxLifetime          string            `yaml:"max_lifetime,omitempty" json:"max_lifetime,omitempty"`
	RefreshBeforeSeconds int64             `yaml:"refresh_before_seconds,omitempty" json:"refresh_before_seconds,omitempty"`
	MaxLifetimeSeconds   int64             `yaml:"max_lifetime_seconds,omitempty" json:"max_lifetime_seconds,omitempty"`
	Material             []RefreshMaterial `yaml:"material,omitempty" json:"material,omitempty"`
	AdditionalOutputs    []RefreshOutput   `yaml:"additional_outputs,omitempty" json:"additional_outputs,omitempty"`
}

type RefreshOutput struct {
	Output     string `yaml:"output" json:"output"`
	Credential string `yaml:"credential" json:"credential"`
}

type RefreshMaterial struct {
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	Required    bool   `yaml:"required,omitempty" json:"required,omitempty"`
	Secret      *bool  `yaml:"secret,omitempty" json:"secret,omitempty"`
}

// TokenGrant describes an optional workload-identity OAuth token exchange.
type TokenGrant struct {
	GrantType           string                       `yaml:"grant_type" json:"grant_type"`
	TokenEndpoint       string                       `yaml:"token_endpoint" json:"token_endpoint"`
	Audience            string                       `yaml:"audience,omitempty" json:"audience,omitempty"`
	JWTSVIDAudience     string                       `yaml:"jwt_svid_audience,omitempty" json:"jwt_svid_audience,omitempty"`
	ClientAssertionType string                       `yaml:"client_assertion_type,omitempty" json:"client_assertion_type,omitempty"`
	Scopes              []string                     `yaml:"scopes,omitempty" json:"scopes,omitempty"`
	CacheTTL            string                       `yaml:"cache_ttl,omitempty" json:"cache_ttl,omitempty"`
	RequestedTokenType  string                       `yaml:"requested_token_type,omitempty" json:"requested_token_type,omitempty"`
	SubjectToken        *SubjectToken                `yaml:"subject_token,omitempty" json:"subject_token,omitempty"`
	AudienceOverrides   []TokenGrantAudienceOverride `yaml:"audience_overrides,omitempty" json:"audience_overrides,omitempty"`
}

type SubjectToken struct {
	Source           string `yaml:"source" json:"source"`
	Credential       string `yaml:"credential,omitempty" json:"credential,omitempty"`
	SubjectTokenType string `yaml:"subject_token_type,omitempty" json:"subject_token_type,omitempty"`
}

type TokenGrantAudienceOverride struct {
	Host     string   `yaml:"host" json:"host"`
	Port     int      `yaml:"port" json:"port"`
	Path     string   `yaml:"path,omitempty" json:"path,omitempty"`
	Audience string   `yaml:"audience,omitempty" json:"audience,omitempty"`
	Scopes   []string `yaml:"scopes,omitempty" json:"scopes,omitempty"`
}

// Instance is a named provider on a gateway (env key refs only, no secret values).
type Instance struct {
	Name    string   `yaml:"name" json:"name"`
	Type    string   `yaml:"type" json:"type"` // profile id
	EnvVars []string `yaml:"env_vars,omitempty" json:"env_vars,omitempty"`
}
