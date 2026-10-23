//go:build !windows

package engine_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/KLORQ/quarshell-policy/corepolicy"
	"github.com/KLORQ/quarshell-policy/engine"
	"github.com/KLORQ/quarshell-policy/internal/tofu"
)

func TestBinaryTOFU(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "curl")
	if err := os.WriteFile(bin, []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	store, err := tofu.Open(filepath.Join(dir, "tofu.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc := policy.Document{Version: 1, Binaries: []string{bin}}
	doc.SetNetworkAllows([]policy.AllowRule{{Host: "example.com", Port: 443}})
	var eng engine.Allowlist
	eng.SetTOFU(store)
	if err := eng.Apply(doc); err != nil {
		t.Fatal(err)
	}
	d, err := eng.Decide(context.Background(), engine.EgressRequest{Host: "example.com", Port: 443, Binary: bin})
	if err != nil || !d.Allow {
		t.Fatalf("first: decision=%v err=%v", d, err)
	}
	if err := os.WriteFile(bin, []byte("changed"), 0o755); err != nil {
		t.Fatal(err)
	}
	d, err = eng.Decide(context.Background(), engine.EgressRequest{Host: "example.com", Port: 443, Binary: bin})
	if err != nil || d.Allow {
		t.Fatalf("expected TOFU deny: decision=%v err=%v", d, err)
	}
}
