package policy

import (
	"strings"
	"testing"
)

func validateSource(t *testing.T, source string) error {
	t.Helper()
	document, err := Parse(strings.NewReader(source), DefaultLimits())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	typed, err := document.Typed()
	if err != nil {
		t.Fatalf("Typed: %v", err)
	}
	return typed.Validate()
}

func TestValidateAcceptsValidPolicy(t *testing.T) {
	source := `version: 1
filesystem_policy:
  read_only: [/usr]
  read_write: [/workspace]
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
network_policies:
  api:
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        rules:
          - allow:
              method: GET
              path: /v1/*
network_middlewares:
  guard:
    middleware: header-injection
    order: 1
    on_error: fail_closed
    endpoints:
      include: ['**.example.com']
`
	if err := validateSource(t, source); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateRejectsInvalidPolicies(t *testing.T) {
	cases := map[string]string{
		"process identity": `version: 1
process:
  run_as_user: root
`,
		"relative path": `version: 1
filesystem_policy:
  read_only: [usr]
`,
		"root write": `version: 1
filesystem_policy:
  read_write: [/]
`,
		"missing port": `version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        protocol: rest
        access: read-only
`,
		"zero port": `version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        port: 0
        protocol: rest
        access: read-only
`,
		"rules and access": `version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        access: read-only
        rules:
          - allow:
              method: GET
`,
		"tcp l7 field": `version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        port: 5432
        protocol: tcp
        path: /v1
`,
		"jsonrpc without rules": `version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        port: 443
        protocol: json-rpc
`,
		"mcp without rules": `version: 1
network_policies:
  api:
    endpoints:
      - host: mcp.example.com
        port: 443
        protocol: mcp
        mcp: {}
`,
		"graphql operation": `version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        port: 443
        protocol: graphql
        rules:
          - allow:
              operation_type: read
`,
		"path shape": `version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        path: v1
        rules:
          - allow:
              method: GET
`,
		"signing without service": `version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        credential_signing: sigv4
        rules:
          - allow:
              method: GET
`,
		"middleware selector": `version: 1
network_middlewares:
  guard:
    middleware: header-injection
    order: 1
    on_error: fail_closed
`,
		"middleware on_error": `version: 1
network_middlewares:
  guard:
    middleware: header-injection
    order: 1
    on_error: fail
    endpoints:
      include: ['**.example.com']
`,
		"duplicate middleware order": `version: 1
network_middlewares:
  first:
    middleware: header-injection
    order: 1
    endpoints:
      include: ['**.example.com']
  second:
    middleware: header-injection
    order: 1
    endpoints:
      include: ['**.example.com']
`,
	}
	for name, source := range cases {
		t.Run(name, func(t *testing.T) {
			if err := validateSource(t, source); err == nil {
				t.Fatalf("invalid policy accepted")
			}
		})
	}
}
