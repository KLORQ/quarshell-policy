package provider

import (
	"strings"
	"sync"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
)

// ReadinessState is the session-bound provider installation state.
type ReadinessState string

const (
	ReadinessPending    ReadinessState = "pending"
	ReadinessInstalling ReadinessState = "installing"
	ReadinessReady      ReadinessState = "ready"
	ReadinessFailed     ReadinessState = "failed"
)

// Readiness is one provider revision bound to a sandbox session.
type Readiness struct {
	Sandbox   domain.SandboxRef
	Provider  domain.ProviderID
	Revision  uint64
	State     ReadinessState
	UpdatedAt time.Time
	Error     string
}

// ReadinessRegistry tracks per-session provider readiness with revision fencing.
type ReadinessRegistry struct {
	mu      sync.Mutex
	entries map[string]Readiness
	now     func() time.Time
	ttl     time.Duration
}

// NewReadinessRegistry returns a registry. Zero ttl means no expiry.
func NewReadinessRegistry(now func() time.Time, ttl time.Duration) *ReadinessRegistry {
	if now == nil {
		now = time.Now
	}
	return &ReadinessRegistry{entries: map[string]Readiness{}, now: now, ttl: ttl}
}

// Begin starts installation for a new provider revision.
func (r *ReadinessRegistry) Begin(sandbox domain.SandboxRef, provider domain.ProviderID, revision uint64) error {
	if !sandbox.Valid() || provider == "" || revision == 0 {
		return domain.Invalidf("provider.readiness", "sandbox, provider and revision are required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := readinessKey(sandbox, provider)
	current, exists := r.entries[key]
	if exists && current.Revision > revision {
		return domain.New(domain.CodeConflict, "provider.readiness", "stale provider revision")
	}
	r.entries[key] = Readiness{Sandbox: sandbox, Provider: provider, Revision: revision, State: ReadinessInstalling, UpdatedAt: r.now()}
	return nil
}

// Ack marks the current revision ready. Stale revisions are rejected.
func (r *ReadinessRegistry) Ack(sandbox domain.SandboxRef, provider domain.ProviderID, revision uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := readinessKey(sandbox, provider)
	current, exists := r.entries[key]
	if !exists || current.Revision != revision {
		return domain.New(domain.CodeConflict, "provider.readiness", "provider revision is not current")
	}
	current.State = ReadinessReady
	current.UpdatedAt = r.now()
	current.Error = ""
	r.entries[key] = current
	return nil
}

// Fail records a failed installation for the current revision.
func (r *ReadinessRegistry) Fail(sandbox domain.SandboxRef, provider domain.ProviderID, revision uint64, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := readinessKey(sandbox, provider)
	current, exists := r.entries[key]
	if !exists || current.Revision != revision {
		return domain.New(domain.CodeConflict, "provider.readiness", "provider revision is not current")
	}
	current.State = ReadinessFailed
	current.UpdatedAt = r.now()
	current.Error = redactReason(reason)
	r.entries[key] = current
	return nil
}

// Get returns a live readiness entry.
func (r *ReadinessRegistry) Get(sandbox domain.SandboxRef, provider domain.ProviderID) (Readiness, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, exists := r.entries[readinessKey(sandbox, provider)]
	if !exists {
		return Readiness{}, false
	}
	if r.ttl > 0 && r.now().Sub(entry.UpdatedAt) > r.ttl {
		delete(r.entries, readinessKey(sandbox, provider))
		return Readiness{}, false
	}
	return entry, true
}

// CloseSession removes every provider entry for one sandbox.
func (r *ReadinessRegistry) CloseSession(sandbox domain.SandboxRef) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, entry := range r.entries {
		if entry.Sandbox == sandbox {
			delete(r.entries, key)
		}
	}
}

func readinessKey(sandbox domain.SandboxRef, provider domain.ProviderID) string {
	return string(sandbox.Workspace) + "/" + string(sandbox.Sandbox) + "/" + string(provider)
}

func redactReason(reason string) string {
	if len(reason) > 512 {
		return reason[:512]
	}
	return strings.TrimSpace(reason)
}
