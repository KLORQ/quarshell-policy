package prover

import "testing"

func TestRiskSafePolicy(t *testing.T) {
	report := Analyze(policyFrom(t, `version: 1
filesystem_policy:
  read_only: [/usr]
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
`))
	if report.Score != 0 || len(report.Findings) != 0 {
		t.Fatalf("report = %+v", report)
	}
}

func TestRiskBroadPolicy(t *testing.T) {
	report := Analyze(policyFrom(t, `version: 1
filesystem_policy:
  read_write: [/]
process:
  run_as_user: root
network_policies:
  all:
    endpoints:
      - host: '*'
        port: 443
        protocol: mcp
        access: full
        mcp:
          allow_all_known_mcp_methods: true
        rules:
          - allow:
              method: '*'
              path: '**'
`))
	if report.Score != 100 {
		t.Fatalf("score = %d", report.Score)
	}
	codes := map[string]bool{}
	for _, finding := range report.Findings {
		codes[finding.Code] = true
	}
	for _, want := range []string{"fs.root_write", "process.root", "net.wildcard_host", "net.full_access", "mcp.allow_all", "l7.allow_all"} {
		if !codes[want] {
			t.Fatalf("missing finding %q in %+v", want, report.Findings)
		}
	}
}

func TestRiskNilPolicy(t *testing.T) {
	if report := Analyze(nil); report.Score != 0 || len(report.Findings) != 0 {
		t.Fatalf("report = %+v", report)
	}
}
