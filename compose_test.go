package policy

import (
	"testing"

	"github.com/KLORQ/quarshell-core/domain"
)

func composeRule(host string) NetworkPolicyRule {
	return NetworkPolicyRule{
		Endpoints: []NetworkEndpoint{{
			Host:     host,
			Port:     domain.Some[uint16](443),
			Ports:    []uint16{443},
			Protocol: "rest",
			Access:   "read-write",
		}},
	}
}

func TestComposeLayersGlobalReplacesSandbox(t *testing.T) {
	global := &Policy{Version: 1, NetworkPolicies: domain.Some(map[string]NetworkPolicyRule{"global": composeRule("global.example.com")})}
	sandbox := &Policy{Version: 1, NetworkPolicies: domain.Some(map[string]NetworkPolicyRule{"sandbox": composeRule("sandbox.example.com")})}
	layers := []ProviderPolicyLayer{{RuleName: "_provider_p", Rule: composeRule("provider.example.com")}}
	effective, source, err := ComposeLayers(global, sandbox, layers)
	if err != nil {
		t.Fatalf("ComposeLayers: %v", err)
	}
	if source != SourceGlobal {
		t.Fatalf("source = %q, want global", source)
	}
	if _, exists := effective.NetworkPolicies.Value["sandbox"]; exists {
		t.Fatalf("sandbox rule survived a global policy")
	}
	if _, exists := effective.NetworkPolicies.Value["global"]; !exists {
		t.Fatalf("global rule missing")
	}
	if _, exists := effective.NetworkPolicies.Value["_provider_p"]; !exists {
		t.Fatalf("provider layer missing")
	}
}

func TestComposeLayersSandboxWhenNoGlobal(t *testing.T) {
	sandbox := &Policy{Version: 1, NetworkPolicies: domain.Some(map[string]NetworkPolicyRule{"sandbox": composeRule("sandbox.example.com")})}
	effective, source, err := ComposeLayers(nil, sandbox, nil)
	if err != nil {
		t.Fatalf("ComposeLayers: %v", err)
	}
	if source != SourceSandbox || !effective.NetworkPolicies.HasValue() {
		t.Fatalf("source = %q, effective = %+v", source, effective)
	}
}

func TestComposeLayersRequiresAuthoredPolicy(t *testing.T) {
	if _, _, err := ComposeLayers(nil, nil, nil); err == nil {
		t.Fatalf("missing authored policy accepted")
	}
	if _, _, err := ComposeLayers(nil, nil, []ProviderPolicyLayer{{RuleName: "_provider_p"}}); err == nil {
		t.Fatalf("provider layers must not stand alone")
	}
}

func TestDerivedHashIsStable(t *testing.T) {
	first := &Policy{Version: 1, NetworkPolicies: domain.Some(map[string]NetworkPolicyRule{
		"a": composeRule("a.example.com"),
		"b": composeRule("b.example.com"),
	})}
	second := &Policy{Version: 1, NetworkPolicies: domain.Some(map[string]NetworkPolicyRule{
		"b": composeRule("b.example.com"),
		"a": composeRule("a.example.com"),
	})}
	firstHash, err := first.DerivedHash()
	if err != nil {
		t.Fatalf("DerivedHash: %v", err)
	}
	secondHash, err := second.DerivedHash()
	if err != nil {
		t.Fatalf("DerivedHash: %v", err)
	}
	if firstHash != secondHash {
		t.Fatalf("map order changed the derived hash")
	}
	second.NetworkPolicies.Value["a"] = composeRule("changed.example.com")
	changedHash, err := second.DerivedHash()
	if err != nil {
		t.Fatalf("DerivedHash: %v", err)
	}
	if changedHash == firstHash {
		t.Fatalf("content change did not change the derived hash")
	}
	var nilPolicy *Policy
	if _, err := nilPolicy.DerivedHash(); err == nil {
		t.Fatalf("nil policy hash accepted")
	}
}

func TestProviderRuleName(t *testing.T) {
	cases := map[string]string{
		"my-github":    "_provider_my_github",
		"Work GitHub!": "_provider_work_github",
		"...":          "_provider_unnamed",
		"":             "_provider_unnamed",
		"a_b":          "_provider_a_b",
	}
	for input, want := range cases {
		if got := ProviderRuleName(input); got != want {
			t.Fatalf("ProviderRuleName(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestIsProviderRuleName(t *testing.T) {
	for _, name := range []string{"_provider_work_github", "_provider_work_github_2", "_provider_"} {
		if !IsProviderRuleName(name) {
			t.Fatalf("%q must use the provider prefix", name)
		}
	}
	for _, name := range []string{"provider_work_github", "custom_provider_work_github", ""} {
		if IsProviderRuleName(name) {
			t.Fatalf("%q must not use the provider prefix", name)
		}
	}
}

func TestStripProviderRuleNames(t *testing.T) {
	policy := &Policy{NetworkPolicies: domain.Some(map[string]NetworkPolicyRule{
		"_provider_work_github": composeRule("github.com"),
		"sandbox_only":          composeRule("sandbox.example.com"),
	})}
	if !StripProviderRuleNames(policy) {
		t.Fatalf("strip reported no change")
	}
	if _, exists := policy.NetworkPolicies.Value["_provider_work_github"]; exists {
		t.Fatalf("provider rule was not removed")
	}
	if _, exists := policy.NetworkPolicies.Value["sandbox_only"]; !exists {
		t.Fatalf("authored rule was removed")
	}
	if StripProviderRuleNames(policy) {
		t.Fatalf("second strip reported a change")
	}
	if StripProviderRuleNames(nil) {
		t.Fatalf("nil policy reported a change")
	}
}

func TestComposeEffectivePolicy(t *testing.T) {
	source := &Policy{
		Version:         1,
		NetworkPolicies: domain.Some(map[string]NetworkPolicyRule{"custom_github": composeRule("api.github.com")}),
	}
	layers := []ProviderPolicyLayer{
		{RuleName: "_provider_work_github", Rule: composeRule("github.com")},
		{RuleName: "_provider_work_github", Rule: composeRule("github.example.com")},
	}
	effective := ComposeEffectivePolicy(source, layers)
	if effective == nil {
		t.Fatalf("nil effective policy")
	}
	if len(effective.NetworkPolicies.Value) != 3 {
		t.Fatalf("effective rules = %d, want 3", len(effective.NetworkPolicies.Value))
	}
	if effective.NetworkPolicies.Value["custom_github"].Endpoints[0].Host != "api.github.com" {
		t.Fatalf("authored rule overwritten")
	}
	if effective.NetworkPolicies.Value["_provider_work_github"].Endpoints[0].Host != "github.com" {
		t.Fatalf("first provider rule missing")
	}
	if effective.NetworkPolicies.Value["_provider_work_github_2"].Endpoints[0].Host != "github.example.com" {
		t.Fatalf("colliding provider rule was not suffixed")
	}
	if len(source.NetworkPolicies.Value) != 1 {
		t.Fatalf("source policy mutated")
	}
	if layers[0].Rule.Name.HasValue() {
		t.Fatalf("layer rule mutated")
	}
}

func TestComposeSetsRuleNameWhenEmpty(t *testing.T) {
	source := &Policy{Version: 1}
	effective := ComposeEffectivePolicy(source, []ProviderPolicyLayer{{RuleName: "_provider_p", Rule: composeRule("p.example.com")}})
	rule := effective.NetworkPolicies.Value["_provider_p"]
	if rule.Name.OrElse("") != "_provider_p" {
		t.Fatalf("rule name = %q", rule.Name.OrElse(""))
	}
}

func TestComposeDeepCopiesMutableFields(t *testing.T) {
	layerRule := composeRule("api.example.com")
	source := &Policy{Version: 1, NetworkPolicies: domain.Some(map[string]NetworkPolicyRule{"authored": composeRule("authored.example.com")})}
	effective := ComposeEffectivePolicy(source, []ProviderPolicyLayer{{RuleName: "_provider_p", Rule: layerRule}})
	provider := effective.NetworkPolicies.Value["_provider_p"]
	provider.Endpoints[0].Host = "changed.example.com"
	provider.Endpoints[0].Ports[0] = 1
	effective.NetworkPolicies.Value["_provider_p"] = provider
	if layerRule.Endpoints[0].Host != "api.example.com" || layerRule.Endpoints[0].Ports[0] != 443 {
		t.Fatalf("layer rule mutated: %+v", layerRule.Endpoints[0])
	}
	authored := effective.NetworkPolicies.Value["authored"]
	authored.Endpoints[0].Host = "changed.example.com"
	effective.NetworkPolicies.Value["authored"] = authored
	if source.NetworkPolicies.Value["authored"].Endpoints[0].Host != "authored.example.com" {
		t.Fatalf("source policy mutated")
	}
}

func TestComposeAbsentNetworkPolicies(t *testing.T) {
	effective := ComposeEffectivePolicy(&Policy{Version: 1}, []ProviderPolicyLayer{{RuleName: "_provider_p", Rule: composeRule("p.example.com")}})
	if !effective.NetworkPolicies.HasValue() || len(effective.NetworkPolicies.Value) != 1 {
		t.Fatalf("network policies = %+v", effective.NetworkPolicies)
	}
}

func TestComposeNilSource(t *testing.T) {
	if ComposeEffectivePolicy(nil, []ProviderPolicyLayer{{RuleName: "_provider_p"}}) != nil {
		t.Fatalf("nil source must stay nil")
	}
}
