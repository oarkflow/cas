package utils

import (
	"fmt"
	"hash/fnv"
	"reflect"
	"sort"
	"strings"
	"unsafe"
)

func ToString(val any) string {
	switch val := val.(type) {
	case string:
		return val
	case []byte:
		return FromByte(val)
	case nil:
		return ""
	case fmt.Stringer:
		return val.String()
	default:
		return fmt.Sprintf("%v", val)
	}
}

func ToInt64(s string) uint64 {
	ft := fnv.New64()
	_, _ = ft.Write([]byte(s))
	return ft.Sum64()
}

func MatchResource(value, pattern string) bool {
	vIndex, pIndex := 0, 0
	vLen, pLen := len(value), len(pattern)

	for pIndex < pLen {
		if pattern[pIndex] == '*' {
			// If '*' is the last character in the pattern, it matches everything
			if pIndex == pLen-1 {
				return true
			}

			// Find the next character in pattern after '*'
			nextChar := pattern[pIndex+1]

			// If the next character is '*', skip it
			if nextChar == '*' {
				pIndex++
				continue
			}

			// Find the next occurrence of the character after '*' in the value
			nextIndex := strings.IndexByte(value[vIndex:], nextChar)

			// If the character is not found, no match
			if nextIndex == -1 {
				return false
			}

			// Move the value index to the next occurrence of the character
			vIndex += nextIndex
		} else if pIndex < pLen && vIndex < vLen && (pattern[pIndex] == value[vIndex] || pattern[pIndex] == ':') {
			// If pattern part matches value part or is a parameter, move to the next parts
			vIndex++
			pIndex++
			// If pattern part is a parameter, skip it in the value
			if pattern[pIndex-1] == ':' {
				// Find the end of the parameter segment
				endIndex := pIndex
				for endIndex < pLen && pattern[endIndex] != '/' {
					endIndex++
				}
				// Skip the parameter segment in the value
				for vIndex < vLen && value[vIndex] != '/' {
					vIndex++
				}
				// Move pattern index to the end of the parameter segment
				pIndex = endIndex
			}
		} else {
			return false
		}
	}

	// If both value and pattern are exhausted, return true
	return vIndex == vLen && pIndex == pLen
}

// ToByte converts a string to a byte slice without memory allocation.
// NOTE: The returned byte slice MUST NOT be modified since it shares the same backing array
// with the given string.
func ToByte(s string) []byte {
	p := unsafe.StringData(s)
	b := unsafe.Slice(p, len(s))
	return b
}

// FromByte converts bytes to a string without memory allocation.
// NOTE: The given bytes MUST NOT be modified since they share the same backing array
// with the returned string.
func FromByte(b []byte) string {
	// Ignore if your IDE shows an error here; it's a false positive.
	p := unsafe.SliceData(b)
	return unsafe.String(p, len(b))
}

func Compact(slice []any) []any {
	keys := make(map[any]struct{})
	result := []any{}
	for _, item := range slice {
		if _, exists := keys[item]; !exists {
			keys[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

func Contains(slice []interface{}, elem interface{}) bool {
	for _, v := range slice {
		if v == elem {
			return true
		}
	}
	return false
}

func Intersection[T any](a, b []T) []T {
	set := make(map[string]struct{})
	var intersection []T

	for _, item := range a {
		set[Serialize(item)] = struct{}{}
	}

	for _, item := range b {
		if _, exists := set[Serialize(item)]; exists {
			intersection = append(intersection, item)
		}
	}

	return intersection
}

func Union[T any](a, b []T) []T {
	set := make(map[string]struct{})
	var union []T

	for _, item := range a {
		set[Serialize(item)] = struct{}{}
		union = append(union, item)
	}

	for _, item := range b {
		if _, exists := set[Serialize(item)]; !exists {
			union = append(union, item)
		}
	}

	return union
}

func Serialize[T any](item T) string {
	v := reflect.ValueOf(item)
	if v.Kind() == reflect.Map {
		keys := v.MapKeys()
		sort.Slice(keys, func(i, j int) bool {
			return keys[i].String() < keys[j].String()
		})
		var builder strings.Builder
		for _, k := range keys {
			builder.WriteString(fmt.Sprintf("%s:%v|", k, v.MapIndex(k)))
		}
		return builder.String()
	}

	var builder strings.Builder
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		builder.WriteString(fmt.Sprintf("%s:%v|", t.Field(i).Name, v.Field(i).Interface()))
	}

	return builder.String()
}
