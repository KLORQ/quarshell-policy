package prover

import (
	"context"
	"strconv"
	"strings"

	"github.com/KLORQ/quarshell-core/domain"
)

// CheckPortsContained asks whether every requested port is in the allowed set.
// A nil solver uses a deterministic subset check.
func CheckPortsContained(ctx context.Context, allowed, requested []uint16, solver Solver) (bool, error) {
	if solver == nil {
		set := make(map[uint16]struct{}, len(allowed))
		for _, port := range allowed {
			set[port] = struct{}{}
		}
		for _, port := range requested {
			if _, ok := set[port]; !ok {
				return false, nil
			}
		}
		return true, nil
	}
	if len(requested) == 0 {
		return true, nil
	}
	if len(allowed) == 0 {
		return false, nil
	}
	script := buildPortScript(allowed, requested)
	answer, err := solver.Solve(ctx, script)
	if err != nil {
		return false, err
	}
	switch answer {
	case Unsat:
		return true, nil
	case Sat:
		return false, nil
	default:
		return false, domain.New(domain.CodeUnavailable, "prover.symbolic", "solver was inconclusive")
	}
}

func buildPortScript(allowed, requested []uint16) string {
	var builder strings.Builder
	builder.WriteString("(set-logic QF_LIA)\n(declare-const p Int)\n(assert (or")
	for _, port := range allowed {
		builder.WriteString(" (= p ")
		builder.WriteString(strconv.Itoa(int(port)))
		builder.WriteString(")")
	}
	builder.WriteString("))\n(assert (not (or")
	for _, port := range requested {
		builder.WriteString(" (= p ")
		builder.WriteString(strconv.Itoa(int(port)))
		builder.WriteString(")")
	}
	builder.WriteString(")))\n(check-sat)\n")
	return builder.String()
}

// SymbolicReport formats a symbolic result for diagnostics.
func SymbolicReport(contained bool, err error) Report {
	if err != nil {
		return Report{Relation: Inconclusive, Reasons: []string{err.Error()}}
	}
	if contained {
		return Report{Relation: Within}
	}
	return Report{Relation: Exceeds, Reasons: []string{"requested port is not in the allowed set"}}
}
