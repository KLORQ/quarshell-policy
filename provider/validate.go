package provider

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/KLORQ/quarshell-policy/corepolicy"
)

// Validate checks a profile document.
func (p Profile) Validate() error {
	id := strings.TrimSpace(p.ID)
	if id == "" {
		return fmt.Errorf("provider profile: id required")
	}
	if !validProfileID(id) {
		return fmt.Errorf("provider profile %q: id must contain lowercase letters, digits, and hyphens", id)
	}
	category := strings.TrimSpace(p.Category)
	switch category {
	case "", "other", "agent", "inference", "source_control", "messaging", "data", "knowledge":
	default:
		return fmt.Errorf("provider profile %q: unsupported category %q", id, category)
	}
	credentials := map[string]Credential{}
	for i, ep := range p.Endpoints {
		if ep.CredentialBinding != nil {
			return fmt.Errorf("provider profile %q: endpoints[%d].credential_binding is sandbox-scoped and cannot be used in a profile", id, i)
		}
		if err := policy.ValidateAllowRule(fmt.Sprintf("endpoints[%d]", i), ep); err != nil {
			return fmt.Errorf("provider profile %q: %w", id, err)
		}
	}
	for i, c := range p.Credentials {
		name := strings.TrimSpace(c.Name)
		if name == "" {
			return fmt.Errorf("provider profile %q: credentials[%d]: name required", id, i)
		}
		if len(c.EnvVars) == 0 && c.Refresh == nil && c.TokenGrant == nil {
			return fmt.Errorf("provider profile %q: credentials[%d]: env_vars required", id, i)
		}
		if _, exists := credentials[name]; exists {
			return fmt.Errorf("provider profile %q: duplicate credential %q", id, name)
		}
		credentials[name] = c
		if c.AuthStyle != "" && c.AuthStyle != "basic" && c.AuthStyle != "bearer" && c.AuthStyle != "header" && c.AuthStyle != "query" && c.AuthStyle != "path" {
			return fmt.Errorf("provider profile %q: credentials[%d].auth_style %q is unsupported (supported: basic, bearer, header, query, path)", id, i, c.AuthStyle)
		}
		if c.AuthStyle == "header" && strings.TrimSpace(c.Header) == "" {
			return fmt.Errorf("provider profile %q: credentials[%d].header_name is required for auth_style header", id, i)
		}
		if c.AuthStyle == "query" && strings.TrimSpace(c.QueryParam) == "" {
			return fmt.Errorf("provider profile %q: credentials[%d].query_param is required for auth_style query", id, i)
		}
		if c.AuthStyle == "path" && strings.TrimSpace(c.PathTemplate) == "" {
			return fmt.Errorf("provider profile %q: credentials[%d].path_template is required for auth_style path", id, i)
		}
		if c.Refresh != nil {
			if c.Refresh.RefreshBeforeSeconds < 0 || c.Refresh.MaxLifetimeSeconds < 0 {
				return fmt.Errorf("provider profile %q: credentials[%d].refresh lifetimes must be non-negative", id, i)
			}
			switch c.Refresh.Strategy {
			case "static", "external", "oauth2_refresh_token", "oauth2_client_credentials", "google_service_account_jwt", "aws_sts_assume_role":
			default:
				return fmt.Errorf("provider profile %q: credentials[%d].refresh.strategy %q is unsupported", id, i, c.Refresh.Strategy)
			}
			if c.Refresh.TokenURL != "" {
				if err := validateTokenEndpoint(c.Refresh.TokenURL); err != nil {
					return fmt.Errorf("provider profile %q: credentials[%d].refresh.token_url: %w", id, i, err)
				}
			}
		}
		if c.TokenGrant != nil {
			if c.TokenGrant.GrantType != "client_credentials" && c.TokenGrant.GrantType != "token_exchange" && c.TokenGrant.GrantType != "ClientCredentials" && c.TokenGrant.GrantType != "TokenExchange" {
				return fmt.Errorf("provider profile %q: credentials[%d].token_grant.grant_type %q is unsupported", id, i, c.TokenGrant.GrantType)
			}
			if err := validateTokenEndpoint(c.TokenGrant.TokenEndpoint); err != nil {
				return fmt.Errorf("provider profile %q: credentials[%d].token_grant.token_endpoint: %w", id, i, err)
			}
		}
	}
	if len(p.Discovery.Credentials) > 0 {
		seen := map[string]struct{}{}
		for _, name := range p.Discovery.Credentials {
			name = strings.TrimSpace(name)
			if _, ok := credentials[name]; !ok {
				return fmt.Errorf("provider profile %q: discovery references unknown credential %q", id, name)
			}
			if _, ok := seen[name]; ok {
				return fmt.Errorf("provider profile %q: duplicate discovery credential %q", id, name)
			}
			seen[name] = struct{}{}
		}
	}
	return nil
}

func validateTokenEndpoint(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("must be an absolute URL with a host")
	}
	if u.User != nil || u.Fragment != "" {
		return fmt.Errorf("must not contain user information or a fragment")
	}
	if u.Scheme == "https" {
		return nil
	}
	host := strings.ToLower(u.Hostname())
	if u.Scheme == "http" && (host == "localhost" || host == "127.0.0.1" || strings.HasSuffix(host, ".svc") || strings.HasSuffix(host, ".svc.cluster.local")) {
		return nil
	}
	return fmt.Errorf("must use HTTPS (HTTP is allowed only for loopback or Kubernetes service DNS)")
}

// ValidateRuntime rejects accepted schema features that quarshell cannot execute
// so import/export compatibility never implies a working credential flow.
func (p Profile) ValidateRuntime() error {
	for i, credential := range p.Credentials {
		if credential.StablePlaceholder {
			return fmt.Errorf("provider profile %q: credentials[%d].stable_placeholder requires endpoint-bound runtime credential handles, which are not supported by this runtime", p.ID, i)
		}
		if credential.TokenGrant != nil {
			grant := strings.ToLower(strings.ReplaceAll(credential.TokenGrant.GrantType, "-", "_"))
			switch grant {
			case "client_credentials":
			case "token_exchange":
				if credential.TokenGrant.SubjectToken == nil || credential.TokenGrant.SubjectToken.Source != "provider_credential" || strings.TrimSpace(credential.TokenGrant.SubjectToken.Credential) == "" {
					return fmt.Errorf("provider profile %q: credentials[%d].token_grant requires a provider_credential subject_token", p.ID, i)
				}
				declared := false
				for _, candidate := range p.Credentials {
					if candidate.Name == credential.TokenGrant.SubjectToken.Credential {
						declared = true
						break
					}
				}
				if !declared {
					return fmt.Errorf("provider profile %q: credentials[%d].token_grant references undeclared subject credential %q", p.ID, i, credential.TokenGrant.SubjectToken.Credential)
				}
			default:
				return fmt.Errorf("provider profile %q: credentials[%d].token_grant.grant_type %q is not supported by quarshell runtime", p.ID, i, credential.TokenGrant.GrantType)
			}
		}
		if credential.Refresh == nil {
			continue
		}
		switch credential.Refresh.Strategy {
		case "oauth2_refresh_token", "oauth2_client_credentials", "oauth2-refresh-token", "oauth2-client-credentials":
			if strings.TrimSpace(credential.Refresh.TokenURL) == "" {
				return fmt.Errorf("provider profile %q: credentials[%d].refresh.token_url is required by quarshell runtime", p.ID, i)
			}
		case "aws_sts_assume_role", "aws-sts-assume-role", "google_service_account_jwt", "google-service-account-jwt":
		default:
			return fmt.Errorf("provider profile %q: credentials[%d].refresh.strategy %q is not supported by quarshell runtime", p.ID, i, credential.Refresh.Strategy)
		}
	}
	for i, endpoint := range p.Endpoints {
		if endpoint.CredentialSigning != "" {
			return fmt.Errorf("provider profile %q: endpoints[%d].credential_signing is not supported by quarshell runtime", p.ID, i)
		}
	}
	return nil
}

func validProfileID(id string) bool {
	if id == "" || id[0] == '-' || id[len(id)-1] == '-' {
		return false
	}
	for _, r := range id {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}
