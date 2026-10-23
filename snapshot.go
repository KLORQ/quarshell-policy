package policy

import (
	"encoding/hex"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
)

// Snapshot is an immutable policy revision. The typed policy is not exposed,
// so callers cannot mutate an active revision in place.
type Snapshot struct {
	revision  domain.PolicyRevision
	hash      [32]byte
	createdAt time.Time
	policy    *Policy
}

// Snapshot converts the document into an immutable revision. Rejecting an
// invalid revision keeps callers from publishing an unvalidated document.
func (d *Document) Snapshot(revision domain.PolicyRevision, createdAt time.Time) (*Snapshot, error) {
	if revision == 0 {
		return nil, domain.Invalidf("policy.snapshot", "revision must be positive")
	}
	typed, err := d.Typed()
	if err != nil {
		return nil, err
	}
	if err := typed.Validate(); err != nil {
		return nil, err
	}
	return &Snapshot{revision: revision, hash: d.Hash, createdAt: createdAt.UTC(), policy: typed}, nil
}

// Revision returns the published revision.
func (s *Snapshot) Revision() domain.PolicyRevision { return s.revision }

// Hash returns the hex source digest used to build this revision.
func (s *Snapshot) Hash() string { return hex.EncodeToString(s.hash[:]) }

// CreatedAt returns the publication time.
func (s *Snapshot) CreatedAt() time.Time { return s.createdAt }

// EvaluateFilesystem evaluates against this revision.
func (s *Snapshot) EvaluateFilesystem(request FilesystemRequest) Decision {
	if s == nil || s.policy == nil {
		return deny("snapshot.nil", "no policy snapshot")
	}
	return s.policy.EvaluateFilesystem(request)
}

// EvaluateProcess evaluates against this revision.
func (s *Snapshot) EvaluateProcess(request ProcessRequest) Decision {
	if s == nil || s.policy == nil {
		return deny("snapshot.nil", "no policy snapshot")
	}
	return s.policy.EvaluateProcess(request)
}

// EvaluateNetwork evaluates against this revision.
func (s *Snapshot) EvaluateNetwork(request NetworkRequest) Decision {
	if s == nil || s.policy == nil {
		return deny("snapshot.nil", "no policy snapshot")
	}
	return s.policy.EvaluateNetwork(request)
}
