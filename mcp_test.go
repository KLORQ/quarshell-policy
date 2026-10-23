package policy

import (
	"strings"
	"testing"
)

func TestCanonicalizeMCPVersions(t *testing.T) {
	input := []string{"2026-07-28", "unknown", "2025-06-18", "2025-03-26", "unknown", "2025-11-25"}
	want := []string{"2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28", "unknown", "unknown"}
	got := CanonicalizeMCPVersions(input)
	if len(got) != len(want) {
		t.Fatalf("length = %d", len(got))
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("canonical[%d] = %q, want %q (all=%v)", index, got[index], want[index], got)
		}
	}
	if input[0] != "2026-07-28" {
		t.Fatalf("input mutated: %v", input)
	}
}

func TestValidateMCPVersions(t *testing.T) {
	if err := ValidateMCPVersions([]string{"2025-06-18", "2025-03-26"}); err != nil {
		t.Fatalf("valid versions rejected: %v", err)
	}
	for name, versions := range map[string][]string{
		"empty":     {},
		"unknown":   {"2020-01-01"},
		"duplicate": {"2025-06-18", "2025-06-18"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateMCPVersions(versions); err == nil {
				t.Fatalf("invalid versions accepted")
			}
		})
	}
}

func typedError(t *testing.T, source string) error {
	t.Helper()
	document, err := Parse(strings.NewReader(source), DefaultLimits())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	_, err = document.Typed()
	return err
}

func TestTypedMCPValidation(t *testing.T) {
	valid := `version: 1
network_policies:
  mcp:
    endpoints:
      - host: mcp.example.com
        port: 443
        protocol: mcp
        mcp:
          versions: [2025-06-18, 2025-03-26]
`
	if err := typedError(t, valid); err != nil {
		t.Fatalf("valid MCP policy rejected: %v", err)
	}
	cases := map[string]string{
		"empty versions": `version: 1
network_policies:
  mcp:
    endpoints:
      - host: mcp.example.com
        port: 443
        protocol: mcp
        mcp:
          versions: []
`,
		"unknown version": `version: 1
network_policies:
  mcp:
    endpoints:
      - host: mcp.example.com
        port: 443
        protocol: mcp
        mcp:
          versions: ["2020-01-01"]
`,
		"duplicate version": `version: 1
network_policies:
  mcp:
    endpoints:
      - host: mcp.example.com
        port: 443
        protocol: mcp
        mcp:
          versions: [2025-06-18, 2025-06-18]
`,
		"mcp options on rest": `version: 1
network_policies:
  rest:
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        mcp: {}
`,
	}
	for name, source := range cases {
		t.Run(name, func(t *testing.T) {
			if err := typedError(t, source); err == nil {
				t.Fatalf("invalid MCP policy accepted")
			}
		})
	}
}

func TestTypedMCPAllowsMissingConfigAndCaseInsensitiveProtocol(t *testing.T) {
	sources := []string{
		`version: 1
network_policies:
  mcp:
    endpoints:
      - host: mcp.example.com
        port: 443
        protocol: mcp
`,
		`version: 1
network_policies:
  mcp:
    endpoints:
      - host: mcp.example.com
        port: 443
        protocol: MCP
        mcp: {}
`,
	}
	for _, source := range sources {
		if err := typedError(t, source); err != nil {
			t.Fatalf("valid MCP policy rejected: %v", err)
		}
	}
}
