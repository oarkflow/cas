package utils

import (
	"reflect"
	"regexp"
	"strings"
)

// IsNil checks if a value is nil
func IsNil(value any) bool {
	return value == nil
}

// IsZero checks if a value is the zero value for its type
func IsZero(value any) bool {
	if IsNil(value) {
		return true
	}
	v := reflect.ValueOf(value)
	return v.IsZero()
}

// MatchType defines the type of matching to perform
type MatchType int

const (
	Exact MatchType = iota
	ContainsMatch
	StartsWith
	EndsWith
	Regex
)

// Operator defines comparison operators for ordered types
type Operator int

const (
	Equal Operator = iota
	NotEqual
	GreaterThan
	LessThan
	GreaterThanOrEqual
	LessThanOrEqual
)

// MatchOptions configures how matching is performed
type MatchOptions struct {
	Type            MatchType
	CaseInsensitive bool
}

// Match checks if two values match based on the provided options
func Match(value, filter any, opts *MatchOptions) (bool, error) {
	if opts == nil {
		opts = &MatchOptions{Type: Exact, CaseInsensitive: false}
	}

	if IsNil(value) || IsNil(filter) {
		return value == filter, nil
	}

	vStr, vOk := value.(string)
	fStr, fOk := filter.(string)

	if !vOk || !fOk {
		// For non-string types, only exact match is supported
		if opts.Type != Exact {
			return false, nil // or return error?
		}
		return reflect.DeepEqual(value, filter), nil
	}

	// String matching
	if opts.CaseInsensitive {
		vStr = strings.ToLower(vStr)
		fStr = strings.ToLower(fStr)
	}

	switch opts.Type {
	case Exact:
		return vStr == fStr, nil
	case ContainsMatch:
		return strings.Contains(vStr, fStr), nil
	case StartsWith:
		return strings.HasPrefix(vStr, fStr), nil
	case EndsWith:
		return strings.HasSuffix(vStr, fStr), nil
	case Regex:
		matched, err := regexp.MatchString(fStr, vStr)
		return matched, err
	default:
		return false, nil
	}
}

// FilterByFields filters a row based on fields using the provided match options
func FilterByFields[T any](filter *T, row *T, opts *MatchOptions, fields ...func(*T) any) (bool, error) {
	for _, field := range fields {
		rowVal := field(row)
		filterVal := field(filter)
		if IsNil(rowVal) || IsNil(filterVal) {
			if rowVal != filterVal {
				return false, nil
			}
			continue
		}
		matched, err := Match(rowVal, filterVal, opts)
		if err != nil {
			return false, err
		}
		if !matched {
			return false, nil
		}
	}
	return true, nil
}

// CompareOrdered compares two ordered values using the specified operator
func CompareOrdered[T Ordered](value, filter T, op Operator) bool {
	switch op {
	case Equal:
		return value == filter
	case NotEqual:
		return value != filter
	case GreaterThan:
		return value > filter
	case LessThan:
		return value < filter
	case GreaterThanOrEqual:
		return value >= filter
	case LessThanOrEqual:
		return value <= filter
	default:
		return false
	}
}

// Ordered constraint for types that support ordering
type Ordered interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 |
		~float32 | ~float64 | ~string
}

// FilterByOrderedField filters by an ordered field with operator
func FilterByOrderedField[T any, U Ordered](row *T, filter U, op Operator, field func(*T) U) bool {
	return CompareOrdered(field(row), filter, op)
}

// JoinFunc is a type for the function that defines the join condition
type JoinFunc[T any, U any] func(t T, u U) bool

// JoinSlices joins two slices by a field or multiple fields using the provided join function
// Optimized version using a map for better performance when possible
func JoinSlices[T any, U any, V any](left []T, right []U, joinFn JoinFunc[T, U], combineFn func(T, U) V) []V {
	var result []V
	rightMap := make(map[any][]U)

	// Try to build a map for right slice if joinFn can be inverted
	// For simplicity, assume joinFn is equality on a key
	// This is a basic optimization; for complex joins, it may not apply
	for _, r := range right {
		// This is simplistic; in practice, you'd need to extract the key
		key := reflect.ValueOf(r).Interface()
		rightMap[key] = append(rightMap[key], r)
	}

	for _, l := range left {
		lKey := reflect.ValueOf(l).Interface()
		if rs, ok := rightMap[lKey]; ok {
			for _, r := range rs {
				if joinFn(l, r) {
					result = append(result, combineFn(l, r))
				}
			}
		}
	}

	// Fallback to original if map doesn't work
	if len(result) == 0 {
		for _, l := range left {
			for _, r := range right {
				if joinFn(l, r) {
					result = append(result, combineFn(l, r))
				}
			}
		}
	}

	return result
}

// FilterSlice filters a slice based on a predicate function
func FilterSlice[T any](slice []T, predicate func(T) bool) []T {
	var result []T
	for _, item := range slice {
		if predicate(item) {
			result = append(result, item)
		}
	}
	return result
}

// FindFirst finds the first item in a slice that matches the predicate
func FindFirst[T any](slice []T, predicate func(T) bool) (T, bool) {
	for _, item := range slice {
		if predicate(item) {
			return item, true
		}
	}
	var zero T
	return zero, false
}
