// Package engine evaluates egress decisions against a policy.Document.
package engine

import (
	"context"
	"fmt"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/KLORQ/quarshell-policy/corepolicy"
	"github.com/KLORQ/quarshell-policy/internal/hostpattern"
	"github.com/KLORQ/quarshell-policy/internal/tofu"
)

// Decision is admit / deny for one request.
type Decision struct {
	Allow   bool
	Audit   bool // true when allowed only because enforcement: audit
	Reason  string
	Matched *MatchedRule
}

// MatchedRule carries the allow-list entry that authorized L4.
type MatchedRule struct {
	ID         string
	Host       string
	Port       int
	AllowedIPs []string
	Rule       policy.AllowRule
}

// EgressRequest is a network attempt to authorize.
type EgressRequest struct {
	Host   string
	Port   int
	Binary string
}

// HTTPRequest is an application-layer request after L4 match.
type HTTPRequest struct {
	Host    string
	Port    int
	Method  string
	Path    string
	Binary  string
	GraphQL *policy.GraphQLOperation
	Query   map[string][]string
}

// PolicyEngine evaluates egress.
type PolicyEngine interface {
	Decide(ctx context.Context, req EgressRequest) (Decision, error)
	DecideHTTP(ctx context.Context, req HTTPRequest) (Decision, error)
	Apply(doc policy.Document) error
}

type compiledEndpoint struct {
	hasHost  bool
	pattern  hostpattern.Pattern
	ports    map[int]struct{}
	rule     policy.AllowRule
	ruleID   string
	binaries []string
}

// Allowlist is a default-deny host/port (+ optional L7) engine.
type Allowlist struct {
	mu         sync.RWMutex
	doc        policy.Document
	endpoints  []compiledEndpoint
	topBins    []string
	anyRuleBin bool
	tofu       *tofu.Store
}

// SetTOFU installs a trust-on-first-use store for binary fingerprints.
func (a *Allowlist) SetTOFU(s *tofu.Store) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tofu = s
}

// Apply replaces the active policy document and compiles host patterns.
func (a *Allowlist) Apply(doc policy.Document) error {
	if err := doc.Validate(); err != nil {
		return err
	}
	var compiled []compiledEndpoint
	anyRuleBin := false
	for _, rule := range doc.AllowRules() {
		ep := compiledEndpoint{
			ports:    make(map[int]struct{}, len(rule.EffectivePorts())),
			rule:     rule,
			binaries: append([]string{}, rule.Binaries...),
		}
		if len(ep.binaries) > 0 {
			anyRuleBin = true
		}
		for _, p := range rule.EffectivePorts() {
			ep.ports[p] = struct{}{}
		}
		ep.ruleID = rule.ID
		if ep.ruleID == "" {
			ep.ruleID = rule.Host
		}
		if strings.TrimSpace(rule.Host) != "" {
			pat, err := hostpattern.Parse(rule.Host)
			if err != nil {
				return fmt.Errorf("policy engine: allow %q host %q: %w", rule.ID, rule.Host, err)
			}
			ep.hasHost = true
			ep.pattern = pat
		} else if len(rule.AllowedIPs) == 0 {
			return fmt.Errorf("policy engine: allow %q: host or allowed_ips required", rule.ID)
		}
		compiled = append(compiled, ep)
	}
	a.mu.Lock()
	a.doc = doc
	a.endpoints = compiled
	a.topBins = append([]string{}, doc.Binaries...)
	a.anyRuleBin = anyRuleBin
	a.mu.Unlock()
	return nil
}

// Decide authorizes host:port (and optional binary). Default deny.
func (a *Allowlist) Decide(ctx context.Context, req EgressRequest) (Decision, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if err := a.gateBinary(req.Binary); err != nil {
		return Decision{Allow: false, Reason: err.Error()}, nil
	}
	ep, ok, binaryUnknown := a.matchL4(req)
	if !ok {
		if binaryUnknown {
			return Decision{Allow: false, Reason: "binary_unknown"}, nil
		}
		return Decision{Allow: false, Reason: "default deny (no matching network_policies)"}, nil
	}
	dec := Decision{
		Allow:  true,
		Reason: "matched network_policies." + ep.ruleID + " " + displayHost(ep) + ":" + strconv.Itoa(req.Port),
		Matched: &MatchedRule{
			ID:         ep.ruleID,
			Host:       req.Host,
			Port:       req.Port,
			AllowedIPs: append([]string{}, ep.rule.AllowedIPs...),
			Rule:       ep.rule,
		},
	}
	if strings.EqualFold(strings.TrimSpace(ep.rule.Protocol), policy.ProtocolSQL) {
		dec.Audit = true
		dec.Reason += " SQL command inspection is unavailable; forwarding in audit mode"
	}
	return dec, nil
}

// DecideHTTP authorizes an HTTP method/path after L4 match.
func (a *Allowlist) DecideHTTP(ctx context.Context, req HTTPRequest) (Decision, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if err := a.gateBinary(req.Binary); err != nil {
		return Decision{Allow: false, Reason: err.Error()}, nil
	}
	ep, ok, binaryUnknown := a.matchL4(EgressRequest{Host: req.Host, Port: req.Port, Binary: req.Binary})
	if !ok {
		if binaryUnknown {
			return Decision{Allow: false, Reason: "binary_unknown"}, nil
		}
		return Decision{Allow: false, Reason: "default deny (no matching network_policies)"}, nil
	}
	matched := &MatchedRule{
		ID:         ep.ruleID,
		Host:       req.Host,
		Port:       req.Port,
		AllowedIPs: append([]string{}, ep.rule.AllowedIPs...),
		Rule:       ep.rule,
	}
	var allow bool
	var reason string
	if req.GraphQL != nil {
		allow, reason = ep.rule.MatchGraphQLQuery(*req.GraphQL, req.Path, req.Query)
	} else {
		allow, reason = ep.rule.MatchHTTPQuery(req.Method, req.Path, req.Query)
	}
	if !allow {
		if ep.rule.IsAudit() {
			return Decision{
				Allow:   true,
				Audit:   true,
				Reason:  "audit: " + reason,
				Matched: matched,
			}, nil
		}
		return Decision{Allow: false, Reason: reason, Matched: matched}, nil
	}
	return Decision{
		Allow:   true,
		Reason:  "matched network_policies." + ep.ruleID + " " + reason,
		Matched: matched,
	}, nil
}

func (a *Allowlist) gateBinary(binary string) error {
	if len(a.topBins) == 0 && !a.anyRuleBin {
		return nil
	}
	if strings.TrimSpace(binary) == "" {
		if len(a.topBins) > 0 {
			return fmt.Errorf("binary_unknown: required by policy.binaries")
		}
		return nil
	}
	if len(a.topBins) > 0 && !binaryAllowed(a.topBins, binary) {
		return fmt.Errorf("binary %q not in policy.binaries", binary)
	}
	if a.tofu != nil {
		if _, err := a.tofu.VerifyOrCache(binary); err != nil {
			return err
		}
	}
	return nil
}

func (a *Allowlist) matchL4(req EgressRequest) (compiledEndpoint, bool, bool) {
	var matches []compiledEndpoint
	binaryUnknown := false
	for _, ep := range a.endpoints {
		if ep.hasHost {
			if !ep.pattern.Match(req.Host) {
				continue
			}
		} else if len(ep.rule.AllowedIPs) == 0 {
			continue
		}
		if _, ok := ep.ports[req.Port]; !ok {
			continue
		}
		if len(ep.binaries) > 0 && strings.TrimSpace(req.Binary) == "" {
			binaryUnknown = true
			continue
		}
		if len(ep.binaries) > 0 {
			if !binaryAllowed(ep.binaries, req.Binary) {
				continue
			}
		}
		matches = append(matches, ep)
	}
	if len(matches) == 0 {
		return compiledEndpoint{}, false, binaryUnknown
	}
	// Prefer provider/inference rules that bind credentials (OpenShell endpoint binding)
	// over bare L4 allow entries when both match the same host:port.
	best := matches[0]
	for _, ep := range matches[1:] {
		bestKeys := len(best.rule.CredentialKeys) > 0
		epKeys := len(ep.rule.CredentialKeys) > 0
		switch {
		case epKeys && !bestKeys:
			best = ep
		case epKeys == bestKeys && ep.rule.NeedsL7() && !best.rule.NeedsL7():
			best = ep
		}
	}
	return best, true, false
}

func displayHost(ep compiledEndpoint) string {
	if ep.hasHost {
		return ep.pattern.Source()
	}
	return "(allowed_ips)"
}

func binaryAllowed(allowed []string, binary string) bool {
	for _, a := range allowed {
		if a == "/**" || a == "*" || a == binary {
			return true
		}
		if matchBinaryGlob(a, binary) {
			return true
		}
	}
	return false
}

// matchBinaryGlob supports Go path.Match plus trailing /** (recursive) and
// mid-path /** segments, so /opt/cursor-agent/** matches
// /opt/cursor-agent/versions/<ver>/node (SO_PEERCRED realpath).
func matchBinaryGlob(pattern, binary string) bool {
	if ok, err := path.Match(pattern, binary); err == nil && ok {
		return true
	}
	if before, ok := strings.CutSuffix(pattern, "/**"); ok {
		prefix := before
		if binary == prefix || strings.HasPrefix(binary, prefix+"/") {
			return true
		}
	}
	if strings.Contains(pattern, "/**/") {
		parts := strings.Split(pattern, "/**/")
		if len(parts) == 2 {
			pre, post := parts[0], parts[1]
			if strings.HasPrefix(binary, pre+"/") {
				rest := binary[len(pre)+1:]
				if ok, err := path.Match(post, path.Base(rest)); err == nil && ok {
					return true
				}
				if ok, err := path.Match("*/"+post, rest); err == nil && ok {
					return true
				}
				// any depth before post
				segs := strings.Split(rest, "/")
				for i := range segs {
					cand := strings.Join(segs[i:], "/")
					if ok, err := path.Match(post, cand); err == nil && ok {
						return true
					}
				}
			}
		}
	}
	return false
}

var _ PolicyEngine = (*Allowlist)(nil)
