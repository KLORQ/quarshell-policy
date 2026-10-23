package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
)

func TestSnapshot(t *testing.T) {
	document, err := Parse(strings.NewReader(evaluatorPolicy), DefaultLimits())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	snapshot, err := document.Snapshot(3, time.Now())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snapshot.Revision() != domain.PolicyRevision(3) {
		t.Fatalf("revision = %d", snapshot.Revision())
	}
	if len(snapshot.Hash()) != 64 {
		t.Fatalf("hash = %q", snapshot.Hash())
	}
	if got := snapshot.EvaluateFilesystem(FilesystemRequest{Path: "/usr/bin/curl", Access: AccessRead}); got.Effect != EffectAllow {
		t.Fatalf("snapshot evaluation = %s (%s)", got.Effect, got.Reason)
	}
}

func TestSnapshotRejectsZeroRevision(t *testing.T) {
	document, err := Parse(strings.NewReader("version: 1\n"), DefaultLimits())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := document.Snapshot(0, time.Now()); err == nil {
		t.Fatalf("zero revision accepted")
	}
}

func TestSnapshotRejectsInvalidTypedPolicy(t *testing.T) {
	document, err := Parse(strings.NewReader(`version: 1
network_policies:
  api:
    endpoints:
      - port: "443"
`), DefaultLimits())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := document.Snapshot(1, time.Now()); err == nil {
		t.Fatalf("invalid typed policy published")
	}
}

func TestNilSnapshotFailsClosed(t *testing.T) {
	var snapshot *Snapshot
	if got := snapshot.EvaluateNetwork(NetworkRequest{}); got.Effect != EffectDeny {
		t.Fatalf("nil snapshot = %s", got.Effect)
	}
}
