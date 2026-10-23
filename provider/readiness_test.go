package provider

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
)

func TestReadinessSessionAndStaleRevision(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	registry := NewReadinessRegistry(func() time.Time { return now }, time.Minute)
	first := domain.SandboxRef{Workspace: "ws", Sandbox: "a"}
	second := domain.SandboxRef{Workspace: "ws", Sandbox: "b"}
	if err := registry.Begin(first, "github", 1); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := registry.Begin(second, "github", 3); err != nil {
		t.Fatalf("Begin second: %v", err)
	}
	if err := registry.Ack(first, "github", 1); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	entry, ok := registry.Get(first, "github")
	if !ok || entry.State != ReadinessReady {
		t.Fatalf("entry = %+v ok=%v", entry, ok)
	}
	if err := registry.Begin(first, "github", 0); err == nil {
		t.Fatalf("zero revision accepted")
	}
	if err := registry.Ack(second, "github", 1); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("stale ack = %v", err)
	}
	if err := registry.Begin(first, "github", 1); err != nil {
		t.Fatalf("same revision re-begin: %v", err)
	}
	registry.CloseSession(first)
	if _, ok := registry.Get(first, "github"); ok {
		t.Fatalf("closed session still visible")
	}
	if _, ok := registry.Get(second, "github"); !ok {
		t.Fatalf("closing one session removed another")
	}
}

func TestReadinessFailureAndExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	registry := NewReadinessRegistry(func() time.Time { return now }, time.Minute)
	ref := domain.SandboxRef{Workspace: "ws", Sandbox: "a"}
	if err := registry.Begin(ref, "github", 1); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := registry.Fail(ref, "github", 1, strings.Repeat("x", 1024)); err != nil {
		t.Fatalf("Fail: %v", err)
	}
	entry, ok := registry.Get(ref, "github")
	if !ok || entry.State != ReadinessFailed || len(entry.Error) != 512 {
		t.Fatalf("entry = %+v ok=%v", entry, ok)
	}
	now = now.Add(2 * time.Minute)
	if _, ok := registry.Get(ref, "github"); ok {
		t.Fatalf("expired readiness still visible")
	}
}
