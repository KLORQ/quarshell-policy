package tofu_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/KLORQ/quarshell-policy/internal/tofu"
)

func TestTOFUFirstThenMismatch(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "tool")
	if err := os.WriteFile(bin, []byte("v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	store, err := tofu.Open(filepath.Join(dir, "tofu.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyOrCache(bin); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyOrCache(bin); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("v2-changed"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyOrCache(bin); err == nil {
		t.Fatal("expected fingerprint mismatch")
	}
}

func TestTOFUCanonicalPathAndConcurrentStores(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "tool")
	if err := os.WriteFile(bin, []byte("v1"), 0755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "tool-alias")
	if err := os.Symlink(bin, alias); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	path := filepath.Join(dir, "tofu.json")
	a, err := tofu.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := tofu.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	for _, tc := range []struct {
		store *tofu.Store
		path  string
	}{{a, bin}, {b, alias}} {
		group.Go(func() {
			if _, err := tc.store.VerifyOrCache(tc.path); err != nil {
				t.Errorf("verify %s: %v", tc.path, err)
			}
		})
	}
	group.Wait()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]string
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(bin)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := filepath.EvalSymlinks(abs)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := data[canon]; !ok {
		t.Fatalf("TOFU did not use canonical path %q: %v", canon, data)
	}
	if _, ok := data[alias]; ok {
		t.Fatalf("TOFU stored symlink alias path: %v", data)
	}
}
