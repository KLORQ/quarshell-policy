package prover

import (
	"strings"

	"github.com/KLORQ/quarshell-policy"
)

// Finding is one risk observation. Codes are stable.
type Finding struct {
	Code     string
	Severity string
	Detail   string
}

// RiskReport is a bounded, deterministic risk summary.
type RiskReport struct {
	Score    int
	Findings []Finding
}

// Analyze reports obvious over-broad grants. It is advisory; it does not
// replace Containment.
func Analyze(policyDocument *policy.Policy) RiskReport {
	report := RiskReport{}
	if policyDocument == nil {
		return report
	}
	add := func(code, severity, detail string, points int) {
		report.Findings = append(report.Findings, Finding{Code: code, Severity: severity, Detail: detail})
		report.Score += points
	}
	if policyDocument.Filesystem.HasValue() {
		for _, path := range policyDocument.Filesystem.Value.ReadWrite {
			if strings.TrimRight(path, "/") == "" {
				add("fs.root_write", "high", "read_write grants the filesystem root", 40)
			}
		}
		for _, path := range policyDocument.Filesystem.Value.ReadOnly {
			if strings.TrimRight(path, "/") == "" {
				add("fs.root_read", "medium", "read_only grants the filesystem root", 20)
			}
		}
	}
	if policyDocument.Process.HasValue() {
		if user := policyDocument.Process.Value.RunAsUser; user.HasValue() && (user.Value == "root" || user.Value == "0") {
			add("process.root", "high", "run_as_user is root", 40)
		}
	}
	if policyDocument.NetworkPolicies.HasValue() {
		for _, rule := range policyDocument.NetworkPolicies.Value {
			for _, endpoint := range rule.Endpoints {
				if endpoint.Host == "*" || endpoint.Host == "**" {
					add("net.wildcard_host", "high", "endpoint allows every host", 40)
				} else if strings.HasPrefix(endpoint.Host, "*.") || strings.HasPrefix(endpoint.Host, "**.") {
					if strings.Count(endpoint.Host, ".") <= 1 {
						add("net.tld_wildcard", "high", "endpoint wildcard covers a top-level domain", 40)
					}
				}
				if endpoint.Access == "full" {
					add("net.full_access", "medium", "endpoint uses access: full", 15)
				}
				if endpoint.Protocol == "" && len(endpoint.Rules) == 0 && endpoint.Access == "" {
					add("net.unrestricted", "medium", "endpoint has no L7 rules or access preset", 15)
				}
				if endpoint.MCP.HasValue() && endpoint.MCP.Value.AllowAllKnownMCPMethods.HasValue() && endpoint.MCP.Value.AllowAllKnownMCPMethods.Value {
					add("mcp.allow_all", "high", "MCP endpoint allows every known method", 30)
				}
				for _, rule := range endpoint.Rules {
					if strings.EqualFold(rule.Allow.Method, "*") && (rule.Allow.Path == "*" || rule.Allow.Path == "**") {
						add("l7.allow_all", "high", "L7 rule allows every method and path", 30)
					}
				}
			}
		}
	}
	if report.Score > 100 {
		report.Score = 100
	}
	return report
}
