package policy

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
	"time"
)

func FuzzParse(f *testing.F) {
	f.Add([]byte("version: 1\n"))
	f.Add([]byte("version: 1\nfilesystem_policy:\n  read_only: [/usr]\n"))
	f.Add([]byte("version: 1\nnetwork_policies:\n  api:\n    endpoints:\n      - host: a\n        port: 443\n"))
	f.Add([]byte("version: 1\nprocess:\n  run_as_user: sandbox\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			t.Skip()
		}
		document, err := Parse(bytes.NewReader(data), DefaultLimits())
		if err != nil {
			return
		}
		_, _ = document.Typed()
	})
}

func TestParseMemoryBudget(t *testing.T) {
	source := "version: 1\n#" + strings.Repeat("x", DefaultLimits().MaxBytes-13) + "\n"
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	started := time.Now()
	if _, err := Parse(strings.NewReader(source), DefaultLimits()); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("parse took %s, budget 2s", elapsed)
	}
	runtime.ReadMemStats(&after)
	const budget = 64 << 20
	allocated := after.TotalAlloc - before.TotalAlloc
	if allocated > budget {
		t.Fatalf("parse allocated %d bytes, budget %d", allocated, budget)
	}
}
