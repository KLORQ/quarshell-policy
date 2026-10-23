// Package policy owns the bounded authored policy parser and its presence-aware
// document model. Evaluation and composition are added in later milestones.
package policy

import "io"

// Limits are the resource budgets applied to one policy document. Defaults
// follow the pinned OpenShell v0.1.4 parser.
type Limits struct {
	MaxBytes            int
	MaxDepth            int
	MaxEvents           int
	MaxNodes            int
	MaxScalarBytes      int
	MaxAliasExpansions  int
	MaxMappingKeys      int
	MaxSequenceElements int
	MaxDocuments        int
	MaxMergeKeys        int
	AliasAnchorRatio    float64
}

// DefaultLimits returns the pinned upstream defaults.
func DefaultLimits() Limits {
	return Limits{
		MaxBytes:            4 << 20,
		MaxDepth:            64,
		MaxEvents:           300_000,
		MaxNodes:            100_000,
		MaxScalarBytes:      4 << 20,
		MaxAliasExpansions:  100,
		MaxMappingKeys:      10_000,
		MaxSequenceElements: 10_000,
		MaxDocuments:        1,
		MaxMergeKeys:        0,
		AliasAnchorRatio:    5.0,
	}
}

// ReadBounded reads at most max bytes and fails instead of buffering more.
func ReadBounded(reader io.Reader, max int) ([]byte, error) {
	if max <= 0 {
		return nil, &BudgetError{Kind: "bytes", Limit: max, Actual: 0}
	}
	body, err := io.ReadAll(io.LimitReader(reader, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(body) > max {
		return nil, &BudgetError{Kind: "bytes", Limit: max, Actual: len(body)}
	}
	return body, nil
}
