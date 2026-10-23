package policy_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KLORQ/quarshell-policy/corepolicy"
	"github.com/KLORQ/quarshell-policy/engine"
	"gopkg.in/yaml.v3"
)

const samplePolicyDocument = `
version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib]
  read_write: [/tmp]
landlock:
  compatibility: best_effort
network_policies:
  anthropic:
    name: anthropic
    endpoints:
      - host: api.anthropic.com
        port: 443
  openai:
    name: openai
    endpoints:
      - host: "*.openai.com"
        ports: [443]
credentials:
  env_allow: [TERM, LANG]
`

func TestParseCompatNaming(t *testing.T) {
	doc, err := policy.Parse([]byte(samplePolicyDocument))
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	if !doc.IncludeWorkdir() {
		t.Fatal("filesystem_policy.include_workdir")
	}
	if doc.HardenMode() != "best_effort" {
		t.Fatalf("mode=%q", doc.HardenMode())
	}
	if len(doc.AllowRules()) != 2 {
		t.Fatalf("allow=%d", len(doc.AllowRules()))
	}
}

func TestPinnedCompatPolicyVersionU32ParseAndEnforcement(t *testing.T) {
	for _, version := range []string{"0", "1", "4294967295"} {
		t.Run(version, func(t *testing.T) {
			doc, err := policy.Parse([]byte("version: " + version + "\n"))
			if err != nil {
				t.Fatalf("parse pinned u32 version: %v", err)
			}
			if doc.Version == 0 && version != "0" || uint64(doc.Version) != mustParseUint32(t, version) {
				t.Fatalf("version=%d, want %s", doc.Version, version)
			}
			if err := doc.Validate(); err != nil {
				t.Fatalf("OpenShell parser accepts this u32 policy version: %v", err)
			}
			var eng engine.Allowlist
			if err := eng.Apply(doc); err != nil {
				t.Fatalf("empty policy with pinned u32 version should apply: %v", err)
			}
		})
	}
	for name, source := range map[string]string{
		"missing":               "network_policies: {}\n",
		"null":                  "version: null\n",
		"negative":              "version: -1\n",
		"overflow":              "version: 4294967296\n",
		"fraction":              "version: 1.5\n",
		"duplicate":             "version: 1\nversion: 1\n",
		"duplicate root member": "version: 1\nprocess: {}\nprocess: {}\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := policy.Parse([]byte(source)); err == nil {
				t.Fatalf("invalid pinned version input accepted: %q", source)
			}
		})
	}
	for _, version := range []string{"0", "1", "4294967295"} {
		var doc policy.Document
		if err := json.Unmarshal([]byte(`{"version":`+version+`}`), &doc); err != nil || uint64(doc.Version) != mustParseUint32(t, version) {
			t.Fatalf("JSON u32 version %s decoded as %d, err=%v", version, doc.Version, err)
		}
	}
	for name, source := range map[string]string{
		"missing":   `{}`,
		"null":      `{"version":null}`,
		"negative":  `{"version":-1}`,
		"overflow":  `{"version":4294967296}`,
		"fraction":  `{"version":1.5}`,
		"duplicate": `{"version":1,"version":1}`,
	} {
		t.Run("json version "+name, func(t *testing.T) {
			var doc policy.Document
			if err := json.Unmarshal([]byte(source), &doc); err == nil {
				t.Fatalf("invalid pinned version input accepted: %s", source)
			}
		})
	}
}

func TestPinnedCompatLandlockEnumDefaultsAndNullValidation(t *testing.T) {
	for _, source := range []string{
		"version: 1\nlandlock: {}\n",
		"version: 1\nlandlock:\n  compatibility: best_effort\n",
	} {
		doc, err := policy.Parse([]byte(source))
		if err != nil || doc.HardenMode() != "best_effort" {
			t.Fatalf("default compatibility for %q = %q, err=%v", source, doc.HardenMode(), err)
		}
	}
	for name, source := range map[string]string{
		"yaml null":      "version: 1\nlandlock:\n  compatibility: null\n",
		"yaml empty":     "version: 1\nlandlock:\n  compatibility: \"\"\n",
		"yaml duplicate": "version: 1\nlandlock:\n  compatibility: best_effort\n  compatibility: hard_requirement\n",
		"yaml unknown":   "version: 1\nlandlock:\n  extra: true\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := policy.Parse([]byte(source)); err == nil {
				t.Fatalf("pinned-invalid landlock value accepted: %q", source)
			}
		})
	}
	for name, source := range map[string]string{
		"null":      `{"version":1,"landlock":{"compatibility":null}}`,
		"empty":     `{"version":1,"landlock":{"compatibility":""}}`,
		"duplicate": `{"version":1,"landlock":{"compatibility":"best_effort","compatibility":"hard_requirement"}}`,
		"unknown":   `{"version":1,"landlock":{"extra":true}}`,
	} {
		t.Run("json "+name, func(t *testing.T) {
			var doc policy.Document
			if err := json.Unmarshal([]byte(source), &doc); err == nil {
				t.Fatalf("pinned-invalid landlock value accepted: %s", source)
			}
		})
	}
}

func TestPinnedCompatProcessIdentityInputsAndValidation(t *testing.T) {
	valid := []struct {
		name, user, group string
	}{
		{"empty process", "", ""},
		{"sandbox user", "sandbox", ""},
		{"minimum", "1", "1"},
		{"numeric maximum", "4294967294", "4294967294"},
		{"independently omitted user", "", "1234"},
		{"independently omitted group", "1234", ""},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			source := "version: 1\nprocess:\n"
			if tc.user == "" {
				source += "  run_as_user: \"\"\n"
			} else {
				source += "  run_as_user: \"" + tc.user + "\"\n"
			}
			if tc.group != "" {
				source += "  run_as_group: \"" + tc.group + "\"\n"
			}
			doc, err := policy.Parse([]byte(source))
			if err != nil {
				t.Fatalf("parse valid ProcessDef: %v", err)
			}
			if err := doc.Validate(); err != nil {
				t.Fatalf("validate valid OpenShell identity: %v", err)
			}
			if doc.ProcessUser() != tc.user || doc.ProcessGroup() != tc.group {
				t.Fatalf("identity = %q:%q, want %q:%q", doc.ProcessUser(), doc.ProcessGroup(), tc.user, tc.group)
			}
		})
	}
	for _, field := range []string{"run_as_user", "run_as_group"} {
		for _, value := range []string{"0", "root", "nobody", "4294967295", "4294967296", "-1", "1.0", " sandbox "} {
			t.Run(field+"="+value, func(t *testing.T) {
				source := "version: 1\nprocess:\n  " + field + ": \"" + value + "\"\n"
				doc, err := policy.Parse([]byte(source))
				if err != nil {
					t.Fatalf("typed string should parse before semantic validation: %v", err)
				}
				if err := doc.Validate(); err == nil {
					t.Fatalf("invalid upstream process identity accepted: %q", value)
				}
			})
		}
	}
	for name, source := range map[string]string{
		"null user":   "version: 1\nprocess:\n  run_as_user: null\n",
		"number user": "version: 1\nprocess:\n  run_as_user: 1000\n",
		"duplicate":   "version: 1\nprocess:\n  run_as_user: sandbox\n  run_as_user: 1000\n",
		"unknown":     "version: 1\nprocess:\n  run_as_other: sandbox\n",
	} {
		t.Run("yaml "+name, func(t *testing.T) {
			if _, err := policy.Parse([]byte(source)); err == nil {
				t.Fatalf("invalid pinned process shape accepted: %q", source)
			}
		})
	}
	for name, source := range map[string]string{
		"null user":   `{"version":1,"process":{"run_as_user":null}}`,
		"number user": `{"version":1,"process":{"run_as_user":1000}}`,
		"duplicate":   `{"version":1,"process":{"run_as_user":"sandbox","run_as_user":"1000"}}`,
		"unknown":     `{"version":1,"process":{"run_as_other":"sandbox"}}`,
	} {
		t.Run("json "+name, func(t *testing.T) {
			var doc policy.Document
			if err := json.Unmarshal([]byte(source), &doc); err == nil {
				t.Fatalf("invalid pinned process shape accepted: %s", source)
			}
		})
	}
}

func mustParseUint32(t *testing.T, value string) uint64 {
	t.Helper()
	var parsed uint64
	if _, err := fmt.Sscan(value, &parsed); err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestNetworkPolicyKeyAndCustomNameSurviveFlattenAndUpdate(t *testing.T) {
	const source = `version: 1
network_policies:
  service_key:
    name: custom-service-name
    endpoints:
      - host: api.example.com
        port: 443
      - host: assets.example.com
        port: 443
  second_service_key:
    name: custom-service-name
    endpoints:
      - host: images.example.com
        port: 443
`
	doc, err := policy.Parse([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	flattened := doc.NetworkAllows()
	if len(flattened) != 3 || flattened[0].ID != "custom-service-name" {
		t.Fatalf("flattened=%+v", flattened)
	}
	doc.SetNetworkAllows(flattened)
	policyRule, ok := doc.NetworkPolicies["service_key"]
	if !ok {
		t.Fatalf("original map key was lost: %#v", doc.NetworkPolicies)
	}
	if policyRule.Name != "custom-service-name" || len(policyRule.Endpoints) != 2 {
		t.Fatalf("policy identity/endpoints changed: %+v", policyRule)
	}
	second, ok := doc.NetworkPolicies["second_service_key"]
	if !ok || second.Name != "custom-service-name" || len(second.Endpoints) != 1 {
		t.Fatalf("duplicate display name must not merge source map keys: %+v", doc.NetworkPolicies)
	}
	encoded, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	reparsed, err := policy.Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if reparsed.NetworkPolicies["service_key"].Name != "custom-service-name" || reparsed.NetworkPolicies["second_service_key"].Name != "custom-service-name" {
		t.Fatalf("round-trip identity changed: %+v", reparsed.NetworkPolicies)
	}
}

func TestRejectRemovedSchema(t *testing.T) {
	_, err := policy.Parse([]byte(`
version: 1
filesystem:
  read: [/usr]
network:
  default: deny
`))
	if err == nil {
		t.Fatal("expected reject of removed filesystem/network keys")
	}
}

func TestEngineAllowDeny(t *testing.T) {
	doc, err := policy.Parse([]byte(samplePolicyDocument))
	if err != nil {
		t.Fatal(err)
	}
	var eng engine.Allowlist
	if err := eng.Apply(doc); err != nil {
		t.Fatal(err)
	}
	ok, err := eng.Decide(context.Background(), engine.EgressRequest{Host: "api.anthropic.com", Port: 443})
	if err != nil || !ok.Allow {
		t.Fatalf("allow: %+v %v", ok, err)
	}
	deny, err := eng.Decide(context.Background(), engine.EgressRequest{Host: "example.com", Port: 443})
	if err != nil || deny.Allow {
		t.Fatalf("deny: %+v %v", deny, err)
	}
}

func TestEmptyNetworkDenyAll(t *testing.T) {
	doc, err := policy.Parse([]byte("version: 1\nnetwork_policies: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	var eng engine.Allowlist
	if err := eng.Apply(doc); err != nil {
		t.Fatal(err)
	}
	d, _ := eng.Decide(context.Background(), engine.EgressRequest{Host: "x.com", Port: 443})
	if d.Allow {
		t.Fatal("expected deny")
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.yaml")
	if err := os.WriteFile(path, []byte(samplePolicyDocument), 0o644); err != nil {
		t.Fatal(err)
	}
	doc, err := policy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	for name, input := range map[string]string{
		"root": `version: 1
filesystem_policy: {}
unknown_option: true
`,
		"removed rego alias": `version: 1
rego_path: deny.rego
`,
		"nested": `version: 1
filesystem_policy:
  include_workdir: true
  surprise: true
`,
		"json-rpc option": `version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        port: 443
        json_rpc:
          surprise: true
`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := policy.Parse([]byte(input)); err == nil {
				t.Fatal("Parse accepted an unknown or unsupported field")
			}
		})
	}
}

func TestFilesystemPolicyIncludeWorkdirCompatDefaultAndRoundTrip(t *testing.T) {
	for _, input := range []string{
		"version: 1\n",
		"version: 1\nfilesystem_policy: {}\n",
		"version: 1\nfilesystem_policy:\n  read_only: [/usr]\n",
	} {
		doc, err := policy.Parse([]byte(input))
		if err != nil {
			t.Fatalf("parse %q: %v", input, err)
		}
		if !doc.IncludeWorkdir() {
			t.Fatalf("OpenShell default include_workdir=false for %q", input)
		}
		encoded, err := yaml.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := policy.Parse(encoded)
		if err != nil || !parsed.IncludeWorkdir() {
			t.Fatalf("round-trip %q: include=%t err=%v", encoded, parsed.IncludeWorkdir(), err)
		}
	}
	doc, err := policy.Parse([]byte("version: 1\nfilesystem_policy:\n  include_workdir: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if doc.IncludeWorkdir() {
		t.Fatal("explicit include_workdir=false was defaulted to true")
	}
	encoded, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := policy.Parse(encoded)
	if err != nil || parsed.IncludeWorkdir() {
		t.Fatalf("explicit false round-trip %q: include=%t err=%v", encoded, parsed.IncludeWorkdir(), err)
	}
}

func TestFilesystemPolicyJSONDefaultAndPresence(t *testing.T) {
	for _, input := range []string{`{}`, `{"read_only":["/usr"]}`} {
		var filesystem policy.FilesystemPolicy
		if err := json.Unmarshal([]byte(input), &filesystem); err != nil {
			t.Fatal(err)
		}
		if !filesystem.IncludeWorkdirEnabled() {
			t.Fatalf("JSON default include_workdir=false for %s", input)
		}
		encoded, err := json.Marshal(filesystem)
		if err != nil {
			t.Fatal(err)
		}
		var roundTrip policy.FilesystemPolicy
		if err := json.Unmarshal(encoded, &roundTrip); err != nil || !roundTrip.IncludeWorkdirEnabled() {
			t.Fatalf("JSON round-trip %s: enabled=%t err=%v", encoded, roundTrip.IncludeWorkdirEnabled(), err)
		}
	}
	var filesystem policy.FilesystemPolicy
	if err := json.Unmarshal([]byte(`{"include_workdir":false}`), &filesystem); err != nil {
		t.Fatal(err)
	}
	if filesystem.IncludeWorkdirEnabled() {
		t.Fatal("explicit JSON false was defaulted to true")
	}
	encoded, err := json.Marshal(filesystem)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip policy.FilesystemPolicy
	if err := json.Unmarshal(encoded, &roundTrip); err != nil || roundTrip.IncludeWorkdirEnabled() {
		t.Fatalf("explicit false JSON round-trip %s: enabled=%t err=%v", encoded, roundTrip.IncludeWorkdirEnabled(), err)
	}
	for _, invalid := range []string{`{"include_workdir":null}`, `{"include_workdir":false,"unknown":true}`, `{"read_only":null}`} {
		if err := json.Unmarshal([]byte(invalid), &filesystem); err == nil {
			t.Errorf("invalid JSON filesystem policy %s accepted", invalid)
		}
	}
}

func TestParseStrictlyValidatesPinnedNetworkMiddlewareSchema(t *testing.T) {
	const valid = `version: 1
network_middlewares:
  redact:
    name: Redact secrets
    middleware: openshell/regex
    order: 10
    config:
      pattern: "token=[^&]+"
      flags: [global, case_insensitive]
    on_error: fail_closed
    endpoints:
      include: ["api.example.com", "*.service.example"]
      exclude: ["internal.example.com"]
`
	doc, err := policy.Parse([]byte(valid))
	if err != nil {
		t.Fatalf("valid pinned middleware config rejected: %v", err)
	}
	if len(doc.NetworkMiddlewares) != 1 {
		t.Fatalf("middleware config was not retained: %+v", doc.NetworkMiddlewares)
	}
	for name, middleware := range map[string]string{
		"unknown field": `version: 1
network_middlewares:
  redactor:
    middleware: openshell/regex
    surprise: true
`,
		"missing required implementation": `version: 1
network_middlewares:
  redactor:
    order: 1
`,
		"unknown selector field": `version: 1
network_middlewares:
  redactor:
    middleware: openshell/regex
    endpoints:
      include: [api.example.com]
      deny: [internal.example.com]
`,
		"non-object implementation config": `version: 1
network_middlewares:
  redactor:
    middleware: openshell/regex
    config: scalar
`,
		"non-i32 order": `version: 1
network_middlewares:
  redactor:
    middleware: openshell/regex
    order: too_late
`,
		"duplicate implementation field": `version: 1
network_middlewares:
  redactor:
    middleware: openshell/regex
    order: 1
    order: 2
`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := policy.Parse([]byte(middleware)); err == nil {
				t.Fatal("Parse accepted invalid pinned middleware schema")
			}
		})
	}
}

func TestValidatePinnedNetworkMiddlewareSemantics(t *testing.T) {
	for name, input := range map[string]string{
		"valid": `version: 1
network_middlewares:
  redact:
    middleware: openshell/regex
    order: 10
    on_error: fail_closed
    endpoints:
      include: ["*.example.com"]
`,
		"missing endpoint selector": `version: 1
network_middlewares:
  redact:
    middleware: openshell/regex
`,
		"empty include": `version: 1
network_middlewares:
  redact:
    middleware: openshell/regex
    endpoints:
      include: []
`,
		"invalid host pattern": `version: 1
network_middlewares:
  redact:
    middleware: openshell/regex
    endpoints:
      include: ["api**.example.com"]
`,
		"invalid on_error": `version: 1
network_middlewares:
  redact:
    middleware: openshell/regex
    on_error: ignore
    endpoints:
      include: ["api.example.com"]
`,
		"duplicate order": `version: 1
network_middlewares:
  redact:
    middleware: openshell/regex
    order: 1
    endpoints:
      include: ["api.example.com"]
  auth:
    middleware: openshell/auth
    order: 1
    endpoints:
      include: ["auth.example.com"]
`,
		"duplicate default order": `version: 1
network_middlewares:
  first:
    middleware: openshell/one
    endpoints:
      include: ["one.example.com"]
  second:
    middleware: openshell/two
    endpoints:
      include: ["two.example.com"]
`,
		"too many selector patterns": `version: 1
network_middlewares:
  redact:
    middleware: openshell/regex
    endpoints:
      include: ["a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com", "f.example.com", "g.example.com", "h.example.com", "i.example.com", "j.example.com", "k.example.com", "l.example.com", "m.example.com", "n.example.com", "o.example.com", "p.example.com", "q.example.com", "r.example.com", "s.example.com", "t.example.com", "u.example.com", "v.example.com", "w.example.com", "x.example.com", "y.example.com", "z.example.com", "aa.example.com", "ab.example.com", "ac.example.com", "ad.example.com", "ae.example.com", "af.example.com", "ag.example.com"]
`,
	} {
		t.Run(name, func(t *testing.T) {
			doc, err := policy.Parse([]byte(input))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			err = doc.Validate()
			if (name == "valid") != (err == nil) {
				t.Fatalf("Validate() error=%v", err)
			}
		})
	}
}

func TestValidateMiddlewareTLSInspectionConflicts(t *testing.T) {
	base := `version: 1
network_policies:
  insecure_tls:
    endpoints:
      - host: api.example.com
        port: 443
        tls: skip
network_middlewares:
  inspect:
    middleware: openshell/inspect
    %s
    endpoints:
      include: ["*.example.com"]
      %s
`
	for _, tc := range []struct {
		name, onError, exclude string
		wantError              bool
	}{
		{"fail closed conflicts", "on_error: fail_closed", "", true},
		{"default conflicts", "", "", true},
		{"fail open is allowed", "on_error: fail_open", "", false},
		{"excluded concrete host is allowed", "on_error: fail_closed", "exclude: [api.example.com]", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := []byte(fmt.Sprintf(base, tc.onError, tc.exclude))
			doc, err := policy.Parse(input)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			err = doc.Validate()
			if (err != nil) != tc.wantError {
				t.Fatalf("Validate() error=%v, wantError=%v", err, tc.wantError)
			}
		})
	}
}

func TestValidateTLSkipWithL7Configuration(t *testing.T) {
	doc, err := policy.Parse([]byte(`version: 1
network_policies:
  explicit_bypass:
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        tls: skip
        access: read-only
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatalf("Validate should accept explicit TLS skip with L7 config: %v", err)
	}
}

func TestParseCompatJSONRPCOptions(t *testing.T) {
	input := `version: 1
network_policies:
  rpc:
    endpoints:
      - host: rpc.example.com
        port: 443
        protocol: json-rpc
        tls: terminate
        json_rpc:
          max_body_bytes: 4096
        rules:
          - allow:
              method: chain_getBlock
`
	doc, err := policy.Parse([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	ep := doc.NetworkPolicies["rpc"].Endpoints[0]
	if ep.JSONRPC == nil || ep.JSONRPC.MaxBodyBytes == nil || *ep.JSONRPC.MaxBodyBytes != 4096 {
		t.Fatalf("JSON-RPC options not retained: %+v", ep.JSONRPC)
	}
}

func TestParseRejectsDuplicateKeysAndDocuments(t *testing.T) {
	for name, input := range map[string]string{
		"duplicate key": `version: 1
version: 1
`,
		"multiple documents": `version: 1
---
version: 1
`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := policy.Parse([]byte(input)); err == nil {
				t.Fatal("Parse accepted ambiguous YAML")
			}
		})
	}
}

func TestParseAcceptsDeprecatedCompatBinaryHarness(t *testing.T) {
	input := `version: 1
network_policies:
  tools:
    endpoints:
      - host: api.example.com
        port: 443
    binaries:
      - path: /usr/bin/agent
        harness: true
`
	doc, err := policy.Parse([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := doc.NetworkPolicies["tools"].Binaries[0].Path; got != "/usr/bin/agent" {
		t.Fatalf("binary path = %q", got)
	}
	if got := doc.NetworkPolicies["tools"].Binaries[0].Harness; !got {
		t.Fatal("deprecated OpenShell harness field was not accepted")
	}
}

func TestParseCompatMCPOptions(t *testing.T) {
	input := `version: 1
network_policies:
  tools:
    endpoints:
      - host: mcp.example.com
        port: 443
        protocol: mcp
        tls: terminate
        mcp:
          versions: ["2025-03-26"]
          max_body_bytes: 131072
          strict_tool_names: false
          allow_all_known_mcp_methods: true
        rules:
          - allow: {}
`
	doc, err := policy.Parse([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	mcp := doc.NetworkPolicies["tools"].Endpoints[0].MCP
	if mcp == nil || mcp.MaxBodyBytes != 131072 || len(mcp.Versions) != 1 || mcp.Versions[0] != "2025-03-26" {
		t.Fatalf("MCP options not retained: %+v", mcp)
	}
	if mcp.StrictToolNames == nil || *mcp.StrictToolNames || mcp.AllowAllKnownMCPMethods == nil || !*mcp.AllowAllKnownMCPMethods {
		t.Fatalf("MCP boolean options not retained: %+v", mcp)
	}
}

func TestParseCompatCredentialBinding(t *testing.T) {
	input := `version: 1
network_policies:
  internal:
    endpoints:
      - host: db.example.com
        port: 5432
        credential_binding:
          provider: database
`
	doc, err := policy.Parse([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := doc.NetworkPolicies["internal"].Endpoints[0].CredentialBinding.Provider; got != "database" {
		t.Fatalf("provider binding=%q", got)
	}
}

func TestCredentialBindingRequiresHostAndExactProviderName(t *testing.T) {
	tests := map[string]policy.AllowRule{
		"host required":       {AllowedIPs: []string{"203.0.113.10"}, Port: 443, CredentialBinding: &policy.CredentialBinding{Provider: "database"}},
		"provider whitespace": {Host: "db.example.com", Port: 5432, CredentialBinding: &policy.CredentialBinding{Provider: " database "}},
	}
	for name, rule := range tests {
		t.Run(name, func(t *testing.T) {
			doc := policy.Document{Version: 1}
			doc.SetNetworkAllows([]policy.AllowRule{rule})
			if err := doc.Validate(); err == nil {
				t.Fatal("expected credential binding validation error")
			}
		})
	}
}

func TestCredentialBindingIsNotAllowedOnInferenceExtension(t *testing.T) {
	doc := policy.Document{Version: 1, Inference: &policy.Inference{
		Allow: []policy.AllowRule{{
			Host: "api.example.com", Port: 443,
			CredentialBinding: &policy.CredentialBinding{Provider: "database"},
		}},
	}}
	if err := doc.Validate(); err == nil || !strings.Contains(err.Error(), "only valid on network_policies endpoints") {
		t.Fatalf("expected inference credential_binding rejection, got %v", err)
	}
}

const sampleInference = `
version: 1
network_policies: {}
inference:
  providers: [anthropic, openai]
  allow:
    - id: custom
      host: llm.example.com
      port: 443
`

func TestInferenceProviders(t *testing.T) {
	doc, err := policy.Parse([]byte(sampleInference))
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatal(err)
	}
	rules := doc.AllowRules()
	if len(rules) != 3 {
		t.Fatalf("allow=%d %+v", len(rules), rules)
	}
	var eng engine.Allowlist
	if err := eng.Apply(doc); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"api.anthropic.com", "api.openai.com", "llm.example.com"} {
		d, err := eng.Decide(context.Background(), engine.EgressRequest{Host: host, Port: 443})
		if err != nil || !d.Allow {
			t.Fatalf("%s: %+v %v", host, d, err)
		}
	}
	deny, _ := eng.Decide(context.Background(), engine.EgressRequest{Host: "evil.example", Port: 443})
	if deny.Allow {
		t.Fatal("expected deny")
	}
}

func TestInferenceUnknownProvider(t *testing.T) {
	doc, err := policy.Parse([]byte("version: 1\ninference:\n  providers: [nope]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := doc.Validate(); err == nil {
		t.Fatal("expected unknown provider error")
	}
}

func TestCredentialEnvKeysFromProviders(t *testing.T) {
	doc, err := policy.Parse([]byte(`
version: 1
inference:
  providers: [anthropic, openai]
credentials:
  env_allow: [TERM]
`))
	if err != nil {
		t.Fatal(err)
	}
	keys := doc.CredentialEnvKeys()
	want := map[string]bool{"TERM": true, "ANTHROPIC_API_KEY": true, "OPENAI_API_KEY": true}
	for _, k := range keys {
		if !want[k] {
			t.Fatalf("unexpected key %q in %v", k, keys)
		}
		delete(want, k)
	}
	if len(want) != 0 {
		t.Fatalf("missing keys %v", want)
	}
}

func TestLandlockHardRequirement(t *testing.T) {
	doc, err := policy.Parse([]byte(`
version: 1
landlock:
  compatibility: hard_requirement
`))
	if err != nil {
		t.Fatal(err)
	}
	if doc.HardenMode() != "required" {
		t.Fatalf("mode=%q", doc.HardenMode())
	}
}

func TestTLSWarningsDeprecatedAndSkipL7On443(t *testing.T) {
	doc, err := policy.Parse([]byte(`
version: 1
network_policies:
  api:
    endpoints:
      - host: api.example.com
        port: 443
        protocol: rest
        tls: terminate
      - host: raw.example.com
        ports: [443]
        protocol: rest
        tls: skip
      - host: other.example.com
        port: 8443
        protocol: rest
        tls: passthrough
`))
	if err != nil {
		t.Fatal(err)
	}
	warnings := doc.TLSWarnings()
	wantContains := []string{
		"'tls: terminate' is deprecated; TLS termination is now automatic. Use 'tls: skip' to explicitly disable. This field will be removed in a future version.",
		"'tls: passthrough' is deprecated; TLS termination is now automatic. Use 'tls: skip' to explicitly disable. This field will be removed in a future version.",
		"'tls: skip' with L7 rules on port 443 — L7 inspection cannot work on encrypted traffic",
	}
	if len(warnings) != 3 {
		t.Fatalf("warnings=%v", warnings)
	}
	joined := strings.Join(warnings, "\n")
	for _, want := range wantContains {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in %v", want, warnings)
		}
	}
}
