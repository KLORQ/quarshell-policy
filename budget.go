package policy

import (
	"errors"
	"fmt"
)

// ErrLimitExceeded marks a parser budget violation.
var ErrLimitExceeded = errors.New("policy limit exceeded")

// BudgetError describes which budget was exceeded.
type BudgetError struct {
	Kind   string
	Limit  int
	Actual int
}

// Error implements error.
func (e *BudgetError) Error() string {
	return fmt.Sprintf("%s budget exceeded: limit=%d actual=%d", e.Kind, e.Limit, e.Actual)
}

// Is matches ErrLimitExceeded.
func (e *BudgetError) Is(target error) bool { return target == ErrLimitExceeded }
