package utils

func IsNil(value any) bool {
	return value == nil
}

func Match(value, filter any) bool {
	return value == filter
}

func FilterByFields[T any](filter *T, row *T, fields ...func(*T) any) bool {
	for _, field := range fields {
		if IsNil(field(row)) || !Match(field(row), field(filter)) {
			return false
		}
	}
	return true
}

// JoinFunc is a type for the function that defines the join condition
type JoinFunc[T any, U any] func(t T, u U) bool

// JoinSlices joins two slices by a field or multiple fields using the provided join function
func JoinSlices[T any, U any, V any](left []T, right []U, joinFn JoinFunc[T, U], combineFn func(T, U) V) []V {
	var result []V
	for _, l := range left {
		for _, r := range right {
			if joinFn(l, r) {
				result = append(result, combineFn(l, r))
			}
		}
	}
	return result
}
