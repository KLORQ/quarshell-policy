package policy

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

func parseBudget(t *testing.T, source string, limits Limits) error {
	t.Helper()
	_, err := Parse(strings.NewReader(source), limits)
	return err
}

func TestBudgetBytesBoundary(t *testing.T) {
	limits := DefaultLimits()
	const prefix = "version: 1\n#"
	const suffix = "\n"
	cases := []struct {
		name    string
		count   int
		size    int
		exceeds bool
	}{
		{"limit-1", limits.MaxBytes - len(prefix) - len(suffix) - 1, limits.MaxBytes - 1, false},
		{"limit", limits.MaxBytes - len(prefix) - len(suffix), limits.MaxBytes, false},
		{"limit+1", limits.MaxBytes - len(prefix) - len(suffix) + 1, limits.MaxBytes + 1, true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			source := prefix + strings.Repeat("x", test.count) + suffix
			if len(source) != test.size {
				t.Fatalf("generated %d bytes, want %d", len(source), test.size)
			}
			err := parseBudget(t, source, limits)
			if test.exceeds {
				if !errors.Is(err, ErrLimitExceeded) {
					t.Fatalf("error = %v, want budget error", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestDefaultLimitsMatchPinnedUpstream(t *testing.T) {
	limits := DefaultLimits()
	cases := []struct {
		name string
		got  int
		want int
	}{
		{"bytes", limits.MaxBytes, 4 << 20},
		{"depth", limits.MaxDepth, 64},
		{"events", limits.MaxEvents, 300_000},
		{"nodes", limits.MaxNodes, 100_000},
		{"scalar bytes", limits.MaxScalarBytes, 4 << 20},
		{"aliases", limits.MaxAliasExpansions, 100},
		{"mapping keys", limits.MaxMappingKeys, 10_000},
		{"sequence elements", limits.MaxSequenceElements, 10_000},
		{"documents", limits.MaxDocuments, 1},
	}
	for _, test := range cases {
		if test.got != test.want {
			t.Fatalf("%s = %d, want %d", test.name, test.got, test.want)
		}
	}
}

func nestedQueryPolicy(depth int) string {
	var builder strings.Builder
	builder.WriteString("version: 1\nnetwork_policies:\n  api:\n    endpoints:\n      - rules:\n          - allow:\n              query: ")
	keys := depth - 8
	for index := 0; index < keys; index++ {
		builder.WriteString("{k")
		builder.WriteString(strconv.Itoa(index))
		builder.WriteString(": ")
	}
	builder.WriteString("true")
	builder.WriteString(strings.Repeat("}", keys))
	builder.WriteString("\n")
	return builder.String()
}

func TestBudgetDepthBoundary(t *testing.T) {
	limits := DefaultLimits()
	if err := parseBudget(t, nestedQueryPolicy(limits.MaxDepth), limits); err != nil {
		t.Fatalf("depth %d rejected: %v", limits.MaxDepth, err)
	}
	if err := parseBudget(t, nestedQueryPolicy(limits.MaxDepth+1), limits); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("depth %d error = %v, want budget error", limits.MaxDepth+1, err)
	}
}

func TestBudgetEventsBoundary(t *testing.T) {
	const source = "version: 1\nprocess: {}\n"
	limits := DefaultLimits()
	limits.MaxEvents = 3
	if err := parseBudget(t, source, limits); err != nil {
		t.Fatalf("events at limit rejected: %v", err)
	}
	limits.MaxEvents = 2
	if err := parseBudget(t, source, limits); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("events over limit error = %v, want budget error", err)
	}
}

func TestBudgetNodesBoundary(t *testing.T) {
	const source = "version: 1\n"
	limits := DefaultLimits()
	limits.MaxNodes = 3
	if err := parseBudget(t, source, limits); err != nil {
		t.Fatalf("nodes at limit rejected: %v", err)
	}
	limits.MaxNodes = 2
	if err := parseBudget(t, source, limits); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("nodes over limit error = %v, want budget error", err)
	}
}

func TestBudgetMappingKeysBoundary(t *testing.T) {
	const source = "version: 1\nprocess: {}\nlandlock: {}\n"
	limits := DefaultLimits()
	limits.MaxMappingKeys = 3
	if err := parseBudget(t, source, limits); err != nil {
		t.Fatalf("keys at limit rejected: %v", err)
	}
	limits.MaxMappingKeys = 2
	if err := parseBudget(t, source, limits); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("keys over limit error = %v, want budget error", err)
	}
}

func TestBudgetSequenceElementsBoundary(t *testing.T) {
	const source = "version: 1\nfilesystem_policy:\n  read_only: [/a, /b, /c]\n"
	limits := DefaultLimits()
	limits.MaxSequenceElements = 3
	if err := parseBudget(t, source, limits); err != nil {
		t.Fatalf("elements at limit rejected: %v", err)
	}
	limits.MaxSequenceElements = 2
	if err := parseBudget(t, source, limits); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("elements over limit error = %v, want budget error", err)
	}
}

func TestBudgetAliasesBoundary(t *testing.T) {
	const source = "version: 1\nfilesystem_policy:\n  read_only: &r [/usr]\n  read_write: *r\n"
	limits := DefaultLimits()
	limits.MaxAliasExpansions = 1
	limits.AliasAnchorRatio = 0
	if err := parseBudget(t, source, limits); err != nil {
		t.Fatalf("alias at limit rejected: %v", err)
	}
	limits.MaxAliasExpansions = 0
	if err := parseBudget(t, source, limits); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("alias over limit error = %v, want budget error", err)
	}
}

func TestBudgetAliasBomb(t *testing.T) {
	var builder strings.Builder
	builder.WriteString("version: 1\nnetwork_middlewares:\n  m:\n    middleware: test\n    config:\n")
	for index := 0; index < 20; index++ {
		builder.WriteString("      anchor")
		builder.WriteString(strconv.Itoa(index))
		builder.WriteString(": &a")
		builder.WriteString(strconv.Itoa(index))
		builder.WriteString(" {x: ")
		builder.WriteString(strconv.Itoa(index))
		builder.WriteString("}\n")
	}
	for index := 0; index < 101; index++ {
		builder.WriteString("      use")
		builder.WriteString(strconv.Itoa(index))
		builder.WriteString(": *a")
		builder.WriteString(strconv.Itoa(index % 20))
		builder.WriteString("\n")
	}
	limits := DefaultLimits()
	if err := parseBudget(t, builder.String(), limits); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("alias bomb error = %v, want budget error", err)
	}
}

func TestBudgetScalarBytesBoundary(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxScalarBytes = 8
	if err := parseBudget(t, "version: 1\nprocess:\n  run_as_user: abcdefg\n", limits); err != nil {
		t.Fatalf("scalar at limit rejected: %v", err)
	}
	if err := parseBudget(t, "version: 1\nprocess:\n  run_as_user: abcdefgh\n", limits); !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("scalar over limit error = %v, want budget error", err)
	}
}

func TestBudgetErrorsAreStable(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxEvents = 1
	_, err := Parse(strings.NewReader("version: 1\n"), limits)
	if !errors.Is(err, ErrLimitExceeded) {
		t.Fatalf("error = %v", err)
	}
	var budget *BudgetError
	if !errors.As(err, &budget) {
		t.Fatalf("error does not wrap BudgetError: %v", err)
	}
	if budget.Kind != "events" || budget.Limit != 1 || budget.Actual != 2 {
		t.Fatalf("budget = %+v", budget)
	}
}
