package provider

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KLORQ/quarshell-policy/corepolicy"
	"gopkg.in/yaml.v3"
)

func TestParseGitHubProfile(t *testing.T) {
	const yaml = `
id: github
category: source_control
binaries: [/usr/bin/gh, /usr/bin/git]
credentials:
  - name: api_token
    env_vars: [GITHUB_TOKEN, GH_TOKEN]
    required: true
endpoints:
  - id: api
    host: api.github.com
    port: 443
    protocol: rest
    tls: terminate
    access: read-only
  - id: git
    host: github.com
    port: 443
    protocol: rest
    tls: terminate
    rules:
      - allow: { method: GET, path: "**" }
      - allow: { method: POST, path: "/**/git-upload-pack" }
`
	p, err := ParseYAML([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "github" || len(p.Endpoints) != 2 {
		t.Fatalf("%+v", p)
	}
	keys := p.EnvKeys()
	if len(keys) != 2 || keys[0] != "GITHUB_TOKEN" || keys[1] != "GH_TOKEN" {
		t.Fatalf("keys=%v", keys)
	}
}

func TestCompatProviderProfileFixtures(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("testdata", "openshell"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		t.Run(strings.TrimSuffix(entry.Name(), ".yaml"), func(t *testing.T) {
			p, err := LoadFile(filepath.Join("testdata", "openshell", entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if p.ID == "" {
				t.Fatal("upstream profile id lost")
			}
		})
	}
}

func TestCompatExtendedProfileFieldsRoundTrip(t *testing.T) {
	input := []byte(`id: custom
resource_version: 7
annotations: {source: "migration"}
source: user
scope: workspace
credentials:
  - name: api_key
    env_vars: [CUSTOM_API_KEY]
    auth_style: query
    query_param: key
    refresh:
      strategy: oauth2_client_credentials
      token_url: https://auth.example/token
      refresh_before_seconds: 30
      additional_outputs:
        - {output: refresh_token, credential: refresh_token}
    token_grant:
      grant_type: client_credentials
      token_endpoint: https://auth.example/token
      audience_overrides:
        - {host: api.example, port: 443, path: /v1/**, audience: api://custom}
discovery:
  credentials: [api_key]
`)
	p, err := ParseYAML(input)
	if err != nil {
		t.Fatal(err)
	}
	if p.ResourceVersion != 7 || p.Annotations["source"] != "migration" || p.Source != "user" || p.Scope != "workspace" || p.Credentials[0].Refresh.RefreshBeforeSeconds != 30 || p.Credentials[0].TokenGrant.AudienceOverrides[0].Audience != "api://custom" {
		t.Fatalf("OpenShell fields lost: %+v", p)
	}
	b, err := yaml.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseYAML(b)
	if err != nil {
		t.Fatalf("marshaled profile did not parse: %v", err)
	}
	if parsed.Source != "user" || parsed.Scope != "workspace" {
		t.Fatalf("server-set metadata lost on round-trip: source=%q scope=%q", parsed.Source, parsed.Scope)
	}
}

func TestProfileParserAcceptsJSONConfiguration(t *testing.T) {
	profile, err := ParseYAML([]byte(`{"id":"json-profile","display_name":"JSON profile","credentials":[{"name":"token","env_vars":["API_TOKEN"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if profile.ID != "json-profile" || profile.Credentials[0].EnvVars[0] != "API_TOKEN" {
		t.Fatalf("JSON profile fields lost: %+v", profile)
	}
}

func TestDiscoveryUsesNamedCredentialsOnly(t *testing.T) {
	p, err := LoadFile(filepath.Join("testdata", "openshell", "codex.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range p.EnvKeys() {
		t.Setenv(key, "")
	}
	t.Setenv("CODEX_AUTH_ACCESS_TOKEN", "access")
	t.Setenv("CODEX_AUTH_REFRESH_TOKEN", "refresh")
	t.Setenv("CODEX_AUTH_ACCOUNT_ID", "account")
	keys, err := p.DiscoverEnvVars()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 3 {
		t.Fatalf("optional id token should not block discovery: %v", keys)
	}
	t.Setenv("CODEX_AUTH_ID_TOKEN", "id")
	keys, err = p.DiscoverEnvVars()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 4 {
		t.Fatalf("discovered keys=%v", keys)
	}
}

func TestProfileParserRejectsUnsupportedFields(t *testing.T) {
	profile := []byte("id: sample\nrefresh: {strategy: oauth2-refresh-token}\n")
	if _, err := ParseYAML(profile); err == nil || !strings.Contains(err.Error(), "field refresh not found") {
		t.Fatalf("expected precise unsupported-field error, got %v", err)
	}
}

func TestProfileParserRejectsMultipleYAMLDocuments(t *testing.T) {
	input := []byte("id: openai\n---\nid: anthropic\n")
	if _, err := ParseYAML(input); err == nil {
		t.Fatal("ParseYAML accepted multiple profile documents")
	}
}

func TestRuntimeValidationAcceptsImplementedTokenGrantAndRejectsMissingSubject(t *testing.T) {
	profile := Profile{ID: "exchange", Credentials: []Credential{{
		Name: "access_token", EnvVars: []string{"ACCESS_TOKEN"},
		TokenGrant: &TokenGrant{GrantType: "token_exchange", TokenEndpoint: "https://issuer.example/token", SubjectToken: &SubjectToken{Source: "provider_credential", Credential: "subject"}},
	}, {
		Name: "subject", EnvVars: []string{"UPSTREAM_TOKEN"},
	}}}
	if err := profile.Validate(); err != nil {
		t.Fatalf("schema validation: %v", err)
	}
	if err := profile.ValidateRuntime(); err != nil {
		t.Fatalf("implemented token grant rejected: %v", err)
	}
	profile.Credentials[0].TokenGrant.SubjectToken.Credential = "missing"
	if err := profile.ValidateRuntime(); err == nil || !strings.Contains(err.Error(), "subject credential") {
		t.Fatalf("missing subject credential should be rejected, got %v", err)
	}
}

func TestStablePlaceholderIsParsedButRejectedForRuntimeUse(t *testing.T) {
	profile, err := ParseYAML([]byte("id: external-auth\ncredentials:\n  - name: assertion\n    env_vars: [EXTERNAL_ASSERTION]\n    stable_placeholder: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !profile.Credentials[0].StablePlaceholder {
		t.Fatal("stable_placeholder was not retained during profile parsing")
	}
	if err := profile.ValidateRuntime(); err == nil || !strings.Contains(err.Error(), "endpoint-bound runtime credential handles") {
		t.Fatalf("runtime validation error = %v", err)
	}
}

func TestProfileRejectsInsecurePublicTokenEndpoint(t *testing.T) {
	for _, endpoint := range []string{"http://issuer.example/token", "file:///tmp/token", "https://user:pass@issuer.example/token"} {
		profile := Profile{ID: "sample", Credentials: []Credential{{
			Name: "access_token", EnvVars: []string{"ACCESS_TOKEN"},
			Refresh: &CredentialRefresh{Strategy: "oauth2_refresh_token", TokenURL: endpoint},
		}}}
		if err := profile.Validate(); err == nil || !strings.Contains(err.Error(), "refresh.token_url") {
			t.Errorf("endpoint %q should be rejected with a token_url diagnostic, got %v", endpoint, err)
		}
	}
}

func TestProfileAcceptsDeprecatedTLSPassthroughAlias(t *testing.T) {
	doc := []byte(`id: sample
credentials:
  - name: api_key
    env_vars: [API_KEY]
endpoints:
  - host: api.example.com
    port: 443
    protocol: rest
    tls: passthrough
    access: read-write
`)
	profile, err := ParseYAML(doc)
	if err != nil {
		t.Fatalf("deprecated passthrough alias should remain accepted: %v", err)
	}
	if got := profile.Endpoints[0].TLS; got != "passthrough" {
		t.Fatalf("tls alias changed during profile load: got %q", got)
	}
}

func TestProfileRejectsSandboxScopedCredentialBinding(t *testing.T) {
	doc := []byte(`id: database
endpoints:
  - host: db.example.com
    port: 5432
    credential_binding:
      provider: attached-database
`)
	if _, err := ParseYAML(doc); err == nil || !strings.Contains(err.Error(), "sandbox-scoped") {
		t.Fatalf("expected sandbox-scoped credential_binding rejection, got %v", err)
	}
}

func TestLoadDirRejectsDuplicateProfileIDs(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.yaml", "b.yaml"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("id: duplicate\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := LoadDir(dir); err == nil || !strings.Contains(err.Error(), "duplicate ID") {
		t.Fatalf("expected duplicate profile error, got %v", err)
	}
}

func TestDiscoverEnvVars(t *testing.T) {
	p := Profile{
		ID:        "github",
		Discovery: Discovery{Credentials: []string{"api_token"}},
		Credentials: []Credential{{
			Name: "api_token", EnvVars: []string{"GITHUB_TOKEN", "GH_TOKEN"}, Required: true,
		}},
	}
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "tok")
	keys, err := p.DiscoverEnvVars()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0] != "GH_TOKEN" {
		t.Fatalf("%v", keys)
	}
	t.Setenv("GITHUB_TOKEN", "primary")
	keys, err = p.DiscoverEnvVars()
	if err != nil || len(keys) != 2 || keys[0] != "GITHUB_TOKEN" || keys[1] != "GH_TOKEN" {
		t.Fatalf("all available aliases must be discovered: keys=%v err=%v", keys, err)
	}
	p.Discovery.Credentials = []string{" api_token "}
	p.Credentials[0].Name = " api_token "
	keys, err = p.DiscoverEnvVars()
	if err != nil || len(keys) != 2 {
		t.Fatalf("discovery names must be trimmed: keys=%v err=%v", keys, err)
	}
	p.Discovery.Credentials = nil
	keys, err = p.DiscoverEnvVars()
	if err != nil || len(keys) != 0 {
		t.Fatalf("empty discovery must not scan credentials: keys=%v err=%v", keys, err)
	}
	p.Discovery.Credentials = []string{"api_token"}
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	if keys, err := p.DiscoverEnvVars(); err != nil || len(keys) != 0 {
		t.Fatalf("missing required credential must not fail discovery: keys=%v err=%v", keys, err)
	}
}

func TestCompatVertexConfigDiscovery(t *testing.T) {
	for _, key := range []string{"VERTEX_AI_PROJECT_ID", "VERTEX_AI_REGION", "GOOGLE_VERTEX_AI_BASE_URL", "VERTEX_AI_BASE_URL", "VERTEX_AI_PUBLISHER"} {
		t.Setenv(key, " ")
	}
	t.Setenv("VERTEX_AI_PROJECT_ID", "project-a")
	t.Setenv("VERTEX_AI_REGION", "us-central1")
	t.Setenv("VERTEX_AI_BASE_URL", "https://vertex.example")
	p := Profile{ID: "google-vertex-ai"}
	config := p.DiscoverConfig()
	if len(config) != 3 || config["VERTEX_AI_PROJECT_ID"] != "project-a" || config["VERTEX_AI_REGION"] != "us-central1" || config["VERTEX_AI_BASE_URL"] != "https://vertex.example" {
		t.Fatalf("Vertex discovery config=%v", config)
	}
	p.ID = "other"
	if config := p.DiscoverConfig(); len(config) != 0 {
		t.Fatalf("unrelated profiles must not discover Vertex configuration: %v", config)
	}
}

func TestEffectivePolicy(t *testing.T) {
	base := policy.Document{Version: 1}
	p := Profile{
		ID: "nvidia",
		Endpoints: []policy.AllowRule{{
			Host: "integrate.api.nvidia.com", Port: 443,
			Protocol: "rest", TLS: "terminate", Access: "read-write",
		}},
		Binaries: []string{"/usr/bin/curl"},
		Credentials: []Credential{{
			Name: "api_key", EnvVars: []string{"NVIDIA_API_KEY"},
		}},
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	out, err := EffectivePolicy(base, []Layer{{InstanceName: "nv", Profile: p}}, false)
	if err != nil {
		t.Fatal(err)
	}
	allows := out.NetworkAllows()
	if len(allows) != 1 {
		t.Fatalf("allow=%d", len(allows))
	}
	if allows[0].ID != "provider.nv.0" {
		t.Fatalf("id=%s", allows[0].ID)
	}
	if len(allows[0].Binaries) != 1 {
		t.Fatalf("binaries=%v", allows[0].Binaries)
	}
	if out.Credentials == nil || len(out.Credentials.EnvAllow) != 1 || out.Credentials.EnvAllow[0] != "NVIDIA_API_KEY" {
		t.Fatalf("env=%v", out.Credentials)
	}
	if len(base.NetworkAllows()) != 0 {
		t.Fatalf("base mutated: %d", len(base.NetworkAllows()))
	}
	fresh := policy.Document{Version: 1}
	suppressed, err := EffectivePolicy(fresh, []Layer{{InstanceName: "nv", Profile: p}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(suppressed.NetworkAllows()) != 0 {
		t.Fatalf("expected suppress, got %d", len(suppressed.NetworkAllows()))
	}
}

func TestEffectivePolicyResolvesCredentialBinding(t *testing.T) {
	base := policy.Document{Version: 1}
	base.SetNetworkAllows([]policy.AllowRule{{
		Host: "db.example.com", Port: 5432,
		CredentialBinding: &policy.CredentialBinding{Provider: "database"},
	}})
	profile := Profile{
		ID:          "database-credentials",
		Credentials: []Credential{{Name: "db_token", EnvVars: []string{"DB_TOKEN"}}},
	}
	layer := Layer{InstanceName: "database", Profile: profile, EnvVars: []string{"DB_TOKEN"}}
	out, err := EffectivePolicy(base, []Layer{layer}, false)
	if err != nil {
		t.Fatal(err)
	}
	rule := out.NetworkAllows()[0]
	if len(rule.CredentialKeys) != 1 || rule.CredentialKeys[0] != "DB_TOKEN" {
		t.Fatalf("endpoint credential keys=%v", rule.CredentialKeys)
	}
	if out.Credentials == nil || len(out.Credentials.EnvAllow) != 1 || out.Credentials.EnvAllow[0] != "DB_TOKEN" {
		t.Fatalf("guest credential allowlist=%+v", out.Credentials)
	}
}

func TestEffectivePolicyRejectsUnresolvableCredentialBinding(t *testing.T) {
	base := policy.Document{Version: 1}
	base.SetNetworkAllows([]policy.AllowRule{{
		Host: "db.example.com", Port: 5432,
		CredentialBinding: &policy.CredentialBinding{Provider: "database"},
	}})
	tests := []struct {
		name   string
		layers []Layer
	}{
		{name: "provider not attached"},
		{name: "profile declares endpoints", layers: []Layer{{
			InstanceName: "database",
			Profile:      Profile{ID: "database", Endpoints: []policy.AllowRule{{Host: "db.example.com", Port: 5432}}, Credentials: []Credential{{Name: "db_token", EnvVars: []string{"DB_TOKEN"}}}},
		}}},
		{name: "credential key not declared", layers: []Layer{{
			InstanceName: "database",
			Profile:      Profile{ID: "database", Credentials: []Credential{{Name: "db_token", EnvVars: []string{"DB_TOKEN"}}}},
			EnvVars:      []string{"OTHER_TOKEN"},
		}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := EffectivePolicy(base, tt.layers, false); err == nil {
				t.Fatal("expected credential binding to fail closed")
			}
		})
	}
}

func TestOmitProviderComposed(t *testing.T) {
	doc := policy.Document{Version: 1}
	doc.SetNetworkAllows([]policy.AllowRule{
		{ID: "github-push", Host: "github.com", Port: 443},
		{ID: "provider.gh.api", Host: "api.github.com", Port: 443},
		{ID: "provider.gh.git", Host: "github.com", Port: 443},
	})
	out, n := OmitProviderComposed(doc)
	if n != 2 {
		t.Fatalf("stripped=%d", n)
	}
	allows := out.NetworkAllows()
	if len(allows) != 1 || allows[0].ID != "github-push" {
		t.Fatalf("%+v", allows)
	}
	if len(doc.NetworkAllows()) != 3 {
		t.Fatalf("input mutated")
	}
	p := Profile{
		ID: "github",
		Endpoints: []policy.AllowRule{
			{ID: "api", Host: "api.github.com", Port: 443, Protocol: "rest", TLS: "terminate", Access: "read-only"},
		},
		Credentials: []Credential{{Name: "t", EnvVars: []string{"GITHUB_TOKEN"}}},
	}
	eff, err := EffectivePolicy(out, []Layer{{InstanceName: "gh", Profile: p}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(eff.NetworkAllows()) != 2 {
		t.Fatalf("effective allow=%d %+v", len(eff.NetworkAllows()), eff.NetworkAllows())
	}
}

func TestAuditMatchHTTP(t *testing.T) {
	rule := policy.AllowRule{
		Host: "api.example.com", Port: 443, Protocol: "rest", TLS: "terminate",
		Access: "read-only", Enforcement: "audit",
	}
	ok, _ := rule.MatchHTTP("POST", "/v1")
	if ok {
		t.Fatal("POST should fail MatchHTTP on read-only")
	}
	if !rule.IsAudit() {
		t.Fatal("expected audit")
	}
}
