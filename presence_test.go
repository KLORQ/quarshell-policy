package policy

import (
	"strings"
	"testing"
)

func TestPresenceAbsentNullAndValue(t *testing.T) {
	absent := typed(t, "version: 1\nfilesystem_policy: {}\n").Filesystem.Value.IncludeWorkdir
	if !absent.IsAbsent() {
		t.Fatalf("absent include_workdir = %+v", absent)
	}
	falseValue := typed(t, "version: 1\nfilesystem_policy:\n  include_workdir: false\n").Filesystem.Value.IncludeWorkdir
	if !falseValue.HasValue() || falseValue.Value {
		t.Fatalf("false include_workdir = %+v", falseValue)
	}
}

func TestPresenceNullScalarIsInvalid(t *testing.T) {
	document, err := Parse(strings.NewReader("version: 1\nfilesystem_policy:\n  include_workdir: null\n"), DefaultLimits())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	filesystem, _ := document.Field("filesystem_policy")
	includeWorkdir, _ := filesystem.Field("include_workdir")
	if !includeWorkdir.IsNull() {
		t.Fatalf("authored null lost: %+v", includeWorkdir)
	}
	if _, err := document.Typed(); err == nil {
		t.Fatalf("null include_workdir accepted by typed decoder")
	}
}

func TestPresenceEmptyObjectAndListStayPresent(t *testing.T) {
	document := parse(t, "version: 1\nfilesystem_policy:\n  read_only: []\nnetwork_policies: {}\n")
	filesystem, ok := document.Field("filesystem_policy")
	if !ok || filesystem.Kind != KindMapping {
		t.Fatalf("filesystem_policy = %+v", filesystem)
	}
	readOnly, ok := filesystem.Field("read_only")
	if !ok || readOnly.Kind != KindSequence || len(readOnly.Items) != 0 {
		t.Fatalf("read_only = %+v", readOnly)
	}
	policies, ok := document.Field("network_policies")
	if !ok || policies.Kind != KindMapping || len(policies.Fields) != 0 {
		t.Fatalf("network_policies = %+v", policies)
	}
}

func TestPresenceZeroAndFalseAreNotNull(t *testing.T) {
	document := parse(t, `version: 1
filesystem_policy:
  include_workdir: false
network_policies:
  api:
    endpoints:
      - host: api.example.com
        port: 0
`)
	filesystem, _ := document.Field("filesystem_policy")
	includeWorkdir, _ := filesystem.Field("include_workdir")
	if includeWorkdir.Kind != KindScalar || includeWorkdir.Tag != "!!bool" || includeWorkdir.Scalar != "false" {
		t.Fatalf("include_workdir = %+v", includeWorkdir)
	}
	policies, _ := document.Field("network_policies")
	api, _ := policies.Field("api")
	endpoints, _ := api.Field("endpoints")
	port, _ := endpoints.Items[0].Field("port")
	if port.Kind != KindScalar || port.Tag != "!!int" || port.Scalar != "0" {
		t.Fatalf("port = %+v", port)
	}
	result := typed(t, `version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        port: 0
`)
	if !result.NetworkPolicies.Value["api"].Endpoints[0].Port.HasValue() {
		t.Fatalf("zero port lost presence")
	}
}

func TestPresenceNullIsNotAbsentForScalarField(t *testing.T) {
	absent := typed(t, "version: 1\nnetwork_policies:\n  api:\n    endpoints:\n      - host: api.example.com\n")
	if !absent.NetworkPolicies.Value["api"].Endpoints[0].Port.IsAbsent() {
		t.Fatalf("absent port = %+v", absent.NetworkPolicies.Value["api"].Endpoints[0].Port)
	}
	document, err := Parse(strings.NewReader("version: 1\nnetwork_policies:\n  api:\n    endpoints:\n      - host: api.example.com\n        port: null\n"), DefaultLimits())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := document.Typed(); err == nil {
		t.Fatalf("null port must be invalid, not absent")
	}
}

func TestPresenceRejectsNestedUnknownField(t *testing.T) {
	source := `version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        port: 443
        unknown_endpoint_field: true
`
	if _, err := Parse(strings.NewReader(source), DefaultLimits()); err == nil {
		t.Fatalf("nested unknown field accepted")
	}
}

func TestPresenceForbiddenNullObject(t *testing.T) {
	if _, err := Parse(strings.NewReader("version: 1\nnetwork_policies:\n  api: null\n"), DefaultLimits()); err == nil {
		t.Fatalf("null network policy object accepted")
	}
}
