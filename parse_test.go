package policy

import (
	"errors"
	"strings"
	"testing"

	"github.com/KLORQ/quarshell-core/domain"
)

func parse(t *testing.T, source string) *Document {
	t.Helper()
	document, err := Parse(strings.NewReader(source), DefaultLimits())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return document
}

func TestParseMinimal(t *testing.T) {
	document := parse(t, "version: 1\n")
	if _, ok := document.Field("process"); ok {
		t.Fatalf("absent process must stay absent")
	}
	if version, err := document.Version(); err != nil || version != 1 {
		t.Fatalf("Version = %d, %v", version, err)
	}
}

func TestParseRejectsNullObjects(t *testing.T) {
	for _, field := range []string{"process", "network_policies", "filesystem_policy", "landlock"} {
		source := "version: 1\n" + field + ": null\n"
		if _, err := Parse(strings.NewReader(source), DefaultLimits()); err == nil {
			t.Fatalf("%s: null must be rejected", field)
		} else if !errors.Is(err, domain.ErrInvalid) {
			t.Fatalf("%s: error = %v", field, err)
		}
	}
}

func TestParseAcceptsAbsentOptionalFields(t *testing.T) {
	document := parse(t, "version: 1\nfilesystem_policy: {}\n")
	field, ok := document.Field("filesystem_policy")
	if !ok || field.Kind != KindMapping {
		t.Fatalf("empty object must be present")
	}
}

func TestParseRejectsUnknownField(t *testing.T) {
	if _, err := Parse(strings.NewReader("version: 1\nunknown: true\n"), DefaultLimits()); err == nil {
		t.Fatalf("unknown field accepted")
	}
}

func TestParseRejectsDuplicateField(t *testing.T) {
	if _, err := Parse(strings.NewReader("version: 1\nversion: 1\n"), DefaultLimits()); err == nil {
		t.Fatalf("duplicate field accepted")
	}
}

func TestParseRejectsMergeKey(t *testing.T) {
	source := "version: 1\nprocess:\n  <<: {run_as_user: root}\n"
	if _, err := Parse(strings.NewReader(source), DefaultLimits()); err == nil {
		t.Fatalf("merge key accepted")
	}
}

func TestParseRejectsUnsupportedVersion(t *testing.T) {
	if _, err := Parse(strings.NewReader("version: 2\n"), DefaultLimits()); err == nil {
		t.Fatalf("version 2 accepted")
	}
}

func TestParseRejectsOversizeInput(t *testing.T) {
	source := "version: 1\n#" + strings.Repeat("x", DefaultLimits().MaxBytes) + "\n"
	if _, err := Parse(strings.NewReader(source), DefaultLimits()); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("oversize error = %v", err)
	}
}

func TestParseAcceptsNestedPolicyShape(t *testing.T) {
	source := `version: 1
filesystem_policy:
  read_only: [/usr]
process:
  run_as_user: sandbox
network_policies:
  api:
    name: api
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        access: read-only
        rules:
          - allow:
              method: GET
              path: /v1/*
    binaries:
      - path: /usr/bin/curl
`
	document := parse(t, source)
	field, ok := document.Field("network_policies")
	if !ok || field.Kind != KindMapping || len(field.Fields) != 1 {
		t.Fatalf("network_policies not decoded")
	}
	rule, ok := field.Field("api")
	if !ok || rule.Kind != KindMapping {
		t.Fatalf("rule not decoded")
	}
	endpoints, ok := rule.Field("endpoints")
	if !ok || endpoints.Kind != KindSequence || len(endpoints.Items) != 1 {
		t.Fatalf("endpoints not decoded")
	}
}

func TestParseDepthBudget(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxDepth = 3
	source := "version: 1\nnetwork_policies:\n  api:\n    endpoints:\n      - host: example.com\n"
	if _, err := Parse(strings.NewReader(source), limits); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("depth error = %v", err)
	}
}

func TestParseMappingBudget(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxMappingKeys = 1
	if _, err := Parse(strings.NewReader("version: 1\nprocess: {}\n"), limits); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("mapping budget error = %v", err)
	}
}

func TestReadBounded(t *testing.T) {
	if _, err := ReadBounded(strings.NewReader("abcd"), 3); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("ReadBounded error = %v", err)
	}
	body, err := ReadBounded(strings.NewReader("abc"), 3)
	if err != nil || string(body) != "abc" {
		t.Fatalf("ReadBounded = %q, %v", body, err)
	}
}
