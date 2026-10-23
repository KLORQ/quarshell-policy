// Package hostpattern implements DNS-label-aware host globs for network policy.
//
// Matching is case-insensitive. A '*' wildcard stays within one DNS label,
// while a label consisting only of '**' consumes one or more labels.
package hostpattern

import (
	"fmt"
	"path"
	"slices"
	"strings"
	"unicode"
)

// Pattern is a validated, compiled DNS host pattern.
type Pattern struct {
	source string
	labels []labelPattern
}

type labelKind int

const (
	labelRecursive labelKind = iota
	labelGlob
)

type labelPattern struct {
	kind    labelKind
	source  string // original label (lowercase); only for labelGlob
	literal bool
}

// Parse validates and compiles a host pattern.
func Parse(pattern string) (Pattern, error) {
	if pattern == "" {
		return Pattern{}, fmt.Errorf("host pattern must not be empty")
	}
	for _, r := range pattern {
		if unicode.IsSpace(r) {
			return Pattern{}, fmt.Errorf("host pattern must not contain whitespace")
		}
		if r == '{' || r == '}' {
			return Pattern{}, fmt.Errorf("host pattern must not contain brace alternates; list each host pattern separately")
		}
	}

	source := strings.ToLower(pattern)
	parts := strings.Split(source, ".")
	if slices.Contains(parts, "") {
		return Pattern{}, fmt.Errorf("host pattern must not contain empty DNS labels")
	}

	labels := make([]labelPattern, 0, len(parts))
	for _, label := range parts {
		if label == "**" {
			labels = append(labels, labelPattern{kind: labelRecursive})
			continue
		}
		// Reject '**' embedded inside a label (e.g. api**.example.com).
		if strings.Contains(label, "**") {
			return Pattern{}, fmt.Errorf("invalid host pattern: '**' must be an entire DNS label")
		}
		if _, err := path.Match(label, "x"); err != nil {
			return Pattern{}, fmt.Errorf("invalid host pattern: %w", err)
		}
		literal := !strings.ContainsAny(label, "*?[")
		labels = append(labels, labelPattern{kind: labelGlob, source: label, literal: literal})
	}
	return Pattern{source: source, labels: labels}, nil
}

// Source returns the normalized (lowercase) pattern string.
func (p Pattern) Source() string { return p.source }

// Match reports whether host matches this pattern.
func (p Pattern) Match(host string) bool {
	host = strings.ToLower(host)
	labels := strings.Split(host, ".")
	return p.matchLabels(labels)
}

// Overlaps reports whether two patterns can match at least one same host.
// It is conservative when both labels contain non-literal globs, matching
// OpenShell's admission-time overlap check.
func (p Pattern) Overlaps(other Pattern) bool {
	type state struct{ left, right int }
	pending := []state{{}}
	visited := map[state]struct{}{}
	for len(pending) > 0 {
		cur := pending[0]
		pending = pending[1:]
		if _, ok := visited[cur]; ok {
			continue
		}
		visited[cur] = struct{}{}
		if cur.left == len(p.labels) && cur.right == len(other.labels) {
			return true
		}
		if cur.left >= len(p.labels) || cur.right >= len(other.labels) {
			continue
		}
		left, right := p.labels[cur.left], other.labels[cur.right]
		switch {
		case left.kind == labelRecursive && right.kind == labelRecursive:
			pending = append(pending, state{cur.left + 1, cur.right + 1}, state{cur.left, cur.right + 1}, state{cur.left + 1, cur.right})
		case left.kind == labelRecursive:
			pending = append(pending, state{cur.left + 1, cur.right + 1}, state{cur.left, cur.right + 1})
		case right.kind == labelRecursive:
			pending = append(pending, state{cur.left + 1, cur.right + 1}, state{cur.left + 1, cur.right})
		case labelsMayOverlap(left, right):
			pending = append(pending, state{cur.left + 1, cur.right + 1})
		}
	}
	return false
}

func labelsMayOverlap(left, right labelPattern) bool {
	switch {
	case left.literal && right.literal:
		return left.source == right.source
	case left.literal:
		ok, _ := path.Match(right.source, left.source)
		return ok
	case right.literal:
		ok, _ := path.Match(left.source, right.source)
		return ok
	default:
		return true
	}
}

// SelectorMayMatchPattern conservatively reports whether the selector can
// match any host admitted by candidate, including its exclusions.
func SelectorMayMatchPattern(include, exclude []Pattern, candidate Pattern) bool {
	for _, included := range include {
		if !included.Overlaps(candidate) {
			continue
		}
		var concrete string
		if candidate.literalHost() {
			concrete = candidate.source
		} else if included.literalHost() {
			concrete = included.source
		}
		excluded := false
		if concrete != "" {
			for _, pattern := range exclude {
				if pattern.Match(concrete) {
					excluded = true
					break
				}
			}
		} else {
			for _, pattern := range exclude {
				if len(pattern.labels) == 1 && pattern.labels[0].kind == labelRecursive || pattern.source == included.source || pattern.source == candidate.source {
					excluded = true
					break
				}
			}
		}
		if !excluded {
			return true
		}
	}
	return false
}

func (p Pattern) literalHost() bool {
	for _, label := range p.labels {
		if label.kind != labelGlob || !label.literal {
			return false
		}
	}
	return true
}

func (p Pattern) matchLabels(host []string) bool {
	if slices.Contains(host, "") {
		return false
	}
	type state struct{ pi, hi int }
	pending := []state{{0, 0}}
	visited := map[state]struct{}{}
	for len(pending) > 0 {
		n := len(pending) - 1
		cur := pending[n]
		pending = pending[:n]
		if _, ok := visited[cur]; ok {
			continue
		}
		visited[cur] = struct{}{}
		if cur.pi == len(p.labels) && cur.hi == len(host) {
			return true
		}
		if cur.pi >= len(p.labels) {
			continue
		}
		lab := p.labels[cur.pi]
		switch lab.kind {
		case labelRecursive:
			if cur.hi < len(host) {
				pending = append(pending, state{cur.pi + 1, cur.hi + 1}, state{cur.pi, cur.hi + 1})
			}
		case labelGlob:
			if cur.hi < len(host) {
				ok, err := path.Match(lab.source, host[cur.hi])
				if err == nil && ok {
					pending = append(pending, state{cur.pi + 1, cur.hi + 1})
				}
			}
		}
	}
	return false
}

// MatchString parses pattern and matches host (one-shot helper).
func MatchString(pattern, host string) (bool, error) {
	p, err := Parse(pattern)
	if err != nil {
		return false, err
	}
	return p.Match(host), nil
}
