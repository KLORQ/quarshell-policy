package policy_test

import (
	"testing"

	"github.com/KLORQ/quarshell-policy/corepolicy"
)

func TestParseEndpointSpec(t *testing.T) {
	ep, err := policy.ParseEndpointSpec("api.github.com:443:read-only:rest:enforce")
	if err != nil {
		t.Fatal(err)
	}
	if ep.Host != "api.github.com" || ep.Port != 443 || ep.Access != "read-only" || ep.Protocol != "rest" || ep.Enforcement != "enforce" {
		t.Fatalf("%+v", ep)
	}
	if _, err := policy.ParseEndpointSpec("bad"); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseEndpointSpecIPv6(t *testing.T) {
	ep, err := policy.ParseEndpointSpec("[2001:db8::1]:443:read-only:rest:enforce")
	if err != nil || ep.Host != "2001:db8::1" || ep.Port != 443 || ep.Access != "read-only" {
		t.Fatalf("IPv6 endpoint: %+v, %v", ep, err)
	}
	for _, invalid := range []string{"[2001:db8::1:443", "[not-ipv6]:443", "example.com:443:read-only:rest:enforce:extra"} {
		if _, err := policy.ParseEndpointSpec(invalid); err == nil {
			t.Fatalf("accepted invalid endpoint %q", invalid)
		}
	}
}

func TestApplyNetworkUpdateMerge(t *testing.T) {
	base := policy.Document{Version: 1}
	base.SetNetworkAllows([]policy.AllowRule{
		{Host: "api.github.com", Port: 443, Protocol: "rest"},
	})
	out, err := policy.ApplyNetworkUpdate(base, policy.NetworkUpdate{
		AddEndpoints: []policy.EndpointSpec{{Host: "api.github.com", Port: 443, Protocol: "rest"}},
		AddAllows:    []policy.MethodPathSpec{{Host: "api.github.com", Port: 443, Method: "POST", Path: "/repos/*/issues"}},
		Binaries:     []string{"/usr/bin/gh"},
	})
	if err != nil {
		t.Fatal(err)
	}
	allows := out.NetworkAllows()
	if len(allows) != 1 {
		t.Fatalf("rules=%d", len(allows))
	}
	r := allows[0]
	if len(r.Rules) != 1 || r.Rules[0].Allow == nil || r.Rules[0].Allow.Method != "POST" {
		t.Fatalf("rules=%+v", r.Rules)
	}
	if len(r.Binaries) != 1 || r.Binaries[0] != "/usr/bin/gh" {
		t.Fatalf("binaries=%v", r.Binaries)
	}
}

func TestApplyNetworkUpdateAddHost(t *testing.T) {
	base := policy.Document{Version: 1}
	out, err := policy.ApplyNetworkUpdate(base, policy.NetworkUpdate{
		AddEndpoints: []policy.EndpointSpec{{Host: "example.com", Port: 443}},
	})
	if err != nil {
		t.Fatal(err)
	}
	allows := out.NetworkAllows()
	if len(allows) != 1 || allows[0].Host != "example.com" {
		t.Fatalf("%+v", allows)
	}
}

func TestApplyNetworkUpdateUsesEveryEffectivePortAndHonorsPortsPrecedence(t *testing.T) {
	const source = `version: 1
network_policies:
  upstream-rule:
    endpoints:
      - host: api.example.com
        port: 8443
        ports: [9443, 10443]
`
	base, err := policy.Parse([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	out, err := policy.ApplyNetworkUpdate(base, policy.NetworkUpdate{
		AddAllows: []policy.MethodPathSpec{{Host: "api.example.com", Port: 10443, Method: "POST", Path: "/items"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	rules := out.NetworkAllows()
	if len(rules) != 1 || len(rules[0].Rules) != 1 {
		t.Fatalf("update for second list port must modify existing endpoint: %+v", rules)
	}
	if rules[0].Rules[0].Allow == nil || rules[0].Rules[0].Allow.Method != "POST" {
		t.Fatalf("L7 rule was not added: %+v", rules[0])
	}

	out, err = policy.ApplyNetworkUpdate(base, policy.NetworkUpdate{
		AddEndpoints: []policy.EndpointSpec{{Host: "api.example.com", Port: 8443}},
	})
	if err != nil {
		t.Fatal(err)
	}
	rules = out.NetworkAllows()
	if len(rules) != 2 {
		t.Fatalf("scalar port shadowed by non-empty ports must not match update: %+v", rules)
	}
}
