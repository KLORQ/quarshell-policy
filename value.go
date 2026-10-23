package policy

import (
	"strconv"
	"strings"

	"github.com/KLORQ/quarshell-core/domain"
)

// Kind is the authored YAML node kind.
type Kind uint8

const (
	KindScalar Kind = iota
	KindMapping
	KindSequence
	KindNull
)

// Entry is one mapping key/value pair. Order is preserved from the document.
type Entry struct {
	Key   string
	Value *Value
}

// Value is a presence-aware authored YAML value. Explicit null is a distinct
// kind, not an empty scalar or absent field.
type Value struct {
	Kind   Kind
	Tag    string
	Scalar string
	Fields []Entry
	Items  []*Value
}

// Field returns a mapping field by exact key.
func (v *Value) Field(name string) (*Value, bool) {
	if v == nil || v.Kind != KindMapping {
		return nil, false
	}
	for _, entry := range v.Fields {
		if entry.Key == name {
			return entry.Value, true
		}
	}
	return nil, false
}

// IsNull reports whether the value is an explicit null.
func (v *Value) IsNull() bool { return v != nil && v.Kind == KindNull }

// StringValue returns a scalar string.
func (v *Value) StringValue(op, path string) (string, error) {
	if v == nil || v.Kind != KindScalar || (v.Tag != "!!str" && v.Tag != "!!timestamp") {
		return "", domain.Invalidf(op, "%s must be a string", path)
	}
	return v.Scalar, nil
}

// Uint32Value returns a scalar unsigned 32-bit integer.
func (v *Value) Uint32Value(op, path string) (uint32, error) {
	raw, err := v.integerValue(op, path)
	if err != nil {
		return 0, err
	}
	parsed, err := strconv.ParseUint(raw, 0, 32)
	if err != nil {
		return 0, domain.Invalidf(op, "%s must be a uint32", path)
	}
	return uint32(parsed), nil
}

// Uint16Value returns a scalar unsigned 16-bit integer.
func (v *Value) Uint16Value(op, path string) (uint16, error) {
	raw, err := v.integerValue(op, path)
	if err != nil {
		return 0, err
	}
	parsed, err := strconv.ParseUint(raw, 0, 16)
	if err != nil {
		return 0, domain.Invalidf(op, "%s must be a uint16", path)
	}
	return uint16(parsed), nil
}

// Int32Value returns a scalar signed 32-bit integer.
func (v *Value) Int32Value(op, path string) (int32, error) {
	raw, err := v.integerValue(op, path)
	if err != nil {
		return 0, err
	}
	parsed, err := strconv.ParseInt(raw, 0, 32)
	if err != nil {
		return 0, domain.Invalidf(op, "%s must be an int32", path)
	}
	return int32(parsed), nil
}

// BoolValue returns a scalar boolean.
func (v *Value) BoolValue(op, path string) (bool, error) {
	if v == nil || v.Kind != KindScalar || v.Tag != "!!bool" {
		return false, domain.Invalidf(op, "%s must be a boolean", path)
	}
	parsed, err := strconv.ParseBool(v.Scalar)
	if err != nil {
		return false, domain.Invalidf(op, "%s must be a boolean", path)
	}
	return parsed, nil
}

func (v *Value) integerValue(op, path string) (string, error) {
	if v == nil || v.Kind != KindScalar || v.Tag != "!!int" {
		return "", domain.Invalidf(op, "%s must be an integer", path)
	}
	return strings.ReplaceAll(v.Scalar, "_", ""), nil
}

// Document is the authored policy AST. Absent, null, and value remain distinct
// through *Value and the Field result.
type Document struct {
	Root *Value
	Hash [32]byte
}

// Field returns a top-level field.
func (d *Document) Field(name string) (*Value, bool) {
	if d == nil || d.Root == nil {
		return nil, false
	}
	return d.Root.Field(name)
}

// Version returns the required policy version.
func (d *Document) Version() (uint32, error) {
	field, ok := d.Field("version")
	if !ok {
		return 0, domain.Invalidf("policy.version", "version is required")
	}
	if field.IsNull() {
		return 0, domain.Invalidf("policy.version", "version must not be null")
	}
	return field.Uint32Value("policy.version", "version")
}
