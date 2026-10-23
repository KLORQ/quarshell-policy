package policy_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/KLORQ/quarshell-policy/corepolicy"
	"gopkg.in/yaml.v3"
)

func TestCompatMCPMatcherRoundTrip(t *testing.T) {
	for _, selector := range []string{`tool: {any: ["safe_*", "read_*"]}`, `params: {name: {any: ["safe_*", "read_*"]}}`, `tool: ignored
              params: {name: {any: ["safe_*", "read_*"]}}`} {
		source := fmt.Sprintf(`version: 1
network_policies:
  mcp:
    endpoints:
      - host: mcp.example.com
        port: 443
        protocol: mcp
        rules:
          - allow:
              method: tools/call
              %s
        deny_rules:
          - method: tools/call
            tool: {any: [safe_delete]}
`, selector)
		doc, err := policy.Parse([]byte(source))
		if err != nil {
			t.Fatal(err)
		}
		if err = doc.Validate(); err != nil {
			t.Fatal(err)
		}
		for _, format := range []string{"yaml", "json"} {
			var restored policy.Document
			if format == "yaml" {
				data, e := yaml.Marshal(doc)
				if e != nil {
					t.Fatal(e)
				}
				restored, err = policy.Parse(data)
			} else {
				data, e := json.Marshal(doc)
				if e != nil {
					t.Fatal(e)
				}
				err = json.Unmarshal(data, &restored)
			}
			if err != nil {
				t.Fatal(err)
			}
			rule := restored.NetworkAllows()[0]
			for name, want := range map[string]bool{"safe_read": true, "read_repo": true, "read_file": true, "safe_delete": false, "ignored": false, "evil": false, "": false} {
				got, reason := rule.MatchHTTP("tools/call", "/\x00"+name)
				if got != want {
					t.Fatalf("%s %s tool=%q allowed=%v want=%v: %s", selector, format, name, got, want, reason)
				}
			}
		}
	}
}

func TestCompatMatcherGlobObjectCanonicalizes(t *testing.T) {
	var matcher policy.QueryMatcher
	if err := yaml.Unmarshal([]byte(`{glob: "safe_*"}`), &matcher); err != nil {
		t.Fatal(err)
	}
	if !matcher.Match("safe_read") || matcher.Match("read_repo") {
		t.Fatal("glob matcher result is incorrect")
	}
	encoded, err := yaml.Marshal(matcher)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != "safe_*\n" {
		t.Fatalf("OpenShell matcher canonical YAML=%q", encoded)
	}
	jsonEncoded, err := json.Marshal(matcher)
	if err != nil {
		t.Fatal(err)
	}
	if string(jsonEncoded) != `"safe_*"` {
		t.Fatalf("OpenShell matcher canonical JSON=%s", jsonEncoded)
	}
}

func TestCompatMatcherRejectsMalformedShapes(t *testing.T) {
	for _, input := range []string{`42`, `true`, `["safe"]`, `{any: null}`, `{any: [true]}`, `{glob: 42}`, `{any: [safe], other: value}`, `{any: [safe], any: [other]}`} {
		var matcher policy.QueryMatcher
		if err := yaml.Unmarshal([]byte(input), &matcher); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
}

func TestCompatToolValidation(t *testing.T) {
	disabled := false
	for _, tc := range []struct {
		name             string
		tool             *policy.QueryMatcher
		params           map[string]policy.QueryMatcher
		method, protocol string
		config           *policy.MCPConfig
	}{
		{name: "empty any", tool: &policy.QueryMatcher{}, method: "tools/call", protocol: "mcp"},
		{name: "wrong method", tool: &policy.QueryMatcher{Any: []string{"safe"}}, method: "tools/list", protocol: "mcp"},
		{name: "wildcard without strict names", tool: &policy.QueryMatcher{Any: []string{"safe_*"}}, method: "tools/call", protocol: "mcp", config: &policy.MCPConfig{StrictToolNames: &disabled}},
		{name: "arguments", params: map[string]policy.QueryMatcher{"arguments.repo": {Any: []string{"safe"}}}, method: "tools/call", protocol: "mcp"},
		{name: "rest tool", tool: &policy.QueryMatcher{Any: []string{"safe"}}, method: "GET", protocol: "rest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := docWithAllows(policy.AllowRule{Host: "mcp.example.com", Port: 443, Protocol: tc.protocol, MCP: tc.config, Rules: []policy.L7Rule{{Allow: &policy.L7Allow{Method: tc.method, Tool: tc.tool, Params: tc.params}}}})
			if err := doc.Validate(); err == nil {
				t.Fatal("accepted invalid matcher")
			}
		})
	}
}

func TestQueryMatcherGlobHasNoPathSeparator(t *testing.T) {
	pattern := "org/*"
	matcher := policy.QueryMatcher{Glob: &pattern}
	if !matcher.Match("org/repo/file") || matcher.Match("other/repo") {
		t.Fatal("glob must use empty delimiter set")
	}
	empty := ""
	if !(&policy.QueryMatcher{Glob: &empty}).Match("") || (&policy.QueryMatcher{}).Match("") {
		t.Fatal("empty glob and empty any must be distinct")
	}
}
