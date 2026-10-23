package prover

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
)

// Solution is a solver answer.
type Solution string

const (
	Sat     Solution = "sat"
	Unsat   Solution = "unsat"
	Unknown Solution = "unknown"
)

// Solver runs one SMT-LIB script.
type Solver interface {
	Solve(context.Context, string) (Solution, error)
}

// Z3 runs the z3 binary. A missing binary is reported as an unsupported error.
type Z3 struct {
	Binary  string
	Timeout time.Duration
}

// Solve executes an SMT-LIB2 script.
func (z *Z3) Solve(ctx context.Context, script string) (Solution, error) {
	binary := z.Binary
	if binary == "" {
		binary = "z3"
	}
	if _, err := exec.LookPath(binary); err != nil {
		return Unknown, domain.Wrap(domain.ErrUnsupported, "prover.z3", "z3 binary is unavailable")
	}
	timeout := z.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	command := exec.CommandContext(runCtx, binary, "-in", "-smt2")
	command.Stdin = strings.NewReader(script)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return Unknown, domain.New(domain.CodeUnavailable, "prover.z3", "z3 execution failed")
	}
	fields := strings.Fields(stdout.String())
	if len(fields) == 0 {
		return Unknown, domain.Invalidf("prover.z3", "z3 returned no answer")
	}
	switch fields[0] {
	case "sat":
		return Sat, nil
	case "unsat":
		return Unsat, nil
	default:
		return Unknown, nil
	}
}
