package prover

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"

	"github.com/KLORQ/quarshell-core/domain"
)

type fakeSolver struct {
	answer Solution
	script string
	err    error
}

func (f *fakeSolver) Solve(_ context.Context, script string) (Solution, error) {
	f.script = script
	return f.answer, f.err
}

func TestCheckPortsContainedFallback(t *testing.T) {
	contained, err := CheckPortsContained(context.Background(), []uint16{443, 8443}, []uint16{443}, nil)
	if err != nil || !contained {
		t.Fatalf("contained = %v %v", contained, err)
	}
	contained, err = CheckPortsContained(context.Background(), []uint16{443}, []uint16{8443}, nil)
	if err != nil || contained {
		t.Fatalf("not contained = %v %v", contained, err)
	}
	if contained, err := CheckPortsContained(context.Background(), nil, nil, nil); err != nil || !contained {
		t.Fatalf("empty = %v %v", contained, err)
	}
}

func TestCheckPortsContainedSolver(t *testing.T) {
	solver := &fakeSolver{answer: Unsat}
	contained, err := CheckPortsContained(context.Background(), []uint16{443}, []uint16{443, 8443}, solver)
	if err != nil || !contained {
		t.Fatalf("unsat = %v %v", contained, err)
	}
	if solver.script == "" || !strings.Contains(solver.script, "(check-sat)") {
		t.Fatalf("script = %q", solver.script)
	}
	solver.answer = Sat
	contained, err = CheckPortsContained(context.Background(), []uint16{443}, []uint16{8443}, solver)
	if err != nil || contained {
		t.Fatalf("sat = %v %v", contained, err)
	}
	solver.answer = Unknown
	if _, err := CheckPortsContained(context.Background(), []uint16{443}, []uint16{8443}, solver); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("unknown = %v", err)
	}
}

func TestSymbolicReportDistinguishesUnsupportedAndInconclusive(t *testing.T) {
	unsupported := domain.Wrap(domain.ErrUnsupported, "test.solver", "solver binary is unavailable")
	contained, err := CheckPortsContained(context.Background(), []uint16{443}, []uint16{443}, &fakeSolver{err: unsupported})
	if contained {
		t.Fatal("solver error reported containment")
	}
	report := SymbolicReport(contained, err)
	if report.Relation != Unsupported || report.Allows() {
		t.Fatalf("unsupported solver report = %+v, want fail-closed unsupported", report)
	}

	contained, err = CheckPortsContained(context.Background(), []uint16{443}, []uint16{443}, &fakeSolver{err: errors.New("solver timed out")})
	if contained {
		t.Fatal("solver timeout reported containment")
	}
	report = SymbolicReport(contained, err)
	if report.Relation != Inconclusive || report.Allows() {
		t.Fatalf("inconclusive solver report = %+v, want fail-closed inconclusive", report)
	}
}

func TestZ3Integration(t *testing.T) {
	if _, err := exec.LookPath("z3"); err != nil {
		t.Skip("z3 is not installed")
	}
	solver := &Z3{}
	contained, err := CheckPortsContained(context.Background(), []uint16{443, 8443}, []uint16{443}, solver)
	if err != nil || !contained {
		t.Fatalf("contained = %v %v", contained, err)
	}
	contained, err = CheckPortsContained(context.Background(), []uint16{443}, []uint16{8443}, solver)
	if err != nil || contained {
		t.Fatalf("not contained = %v %v", contained, err)
	}
}
