// Package main provides examples for the enhanced filters package.
//
// To run these examples, you can either:
// 1. Create a separate main.go file that calls RunFiltersExamples()
// 2. Or run: go run examples/filters_examples.go
//
// Note: This file contains examples only and should not be included in the main build.
package main

import (
	"fmt"
	"log"

	"github.com/oarkflow/cas/utils"
)

// User represents a sample struct for filtering examples
type User struct {
	ID     int
	Name   string
	Age    int
	Email  string
	Active bool
	Score  float64
}

// Product represents another sample struct
type Product struct {
	ID    int
	Name  string
	Price float64
}

func main() {
	fmt.Println("=== Filters Package Examples ===\n")

	// Sample data
	users := []User{
		{ID: 1, Name: "Alice", Age: 25, Email: "alice@example.com", Active: true, Score: 85.5},
		{ID: 2, Name: "Bob", Age: 30, Email: "bob@example.com", Active: false, Score: 92.0},
		{ID: 3, Name: "Charlie", Age: 35, Email: "charlie@example.com", Active: true, Score: 78.3},
		{ID: 4, Name: "Diana", Age: 28, Email: "diana@example.com", Active: true, Score: 88.7},
	}

	products := []Product{
		{ID: 1, Name: "Laptop", Price: 999.99},
		{ID: 2, Name: "Mouse", Price: 25.50},
		{ID: 3, Name: "Keyboard", Price: 75.00},
	}

	// Example 1: Basic IsNil and IsZero
	fmt.Println("1. IsNil and IsZero Examples:")
	var nilPtr *string
	var zeroStr string
	var nonZeroStr = "hello"
	fmt.Printf("IsNil(nilPtr): %v\n", utils.IsNil(nilPtr))
	fmt.Printf("IsZero(zeroStr): %v\n", utils.IsZero(zeroStr))
	fmt.Printf("IsZero(nonZeroStr): %v\n", utils.IsZero(nonZeroStr))
	fmt.Println()

	// Example 2: Enhanced Match with different types
	fmt.Println("2. Enhanced Match Examples:")
	opts := &utils.MatchOptions{Type: utils.Exact, CaseInsensitive: false}

	// Exact match
	matched, err := utils.Match("Alice", "Alice", opts)
	if err != nil {
		log.Printf("Error: %v", err)
	}
	fmt.Printf("Exact match 'Alice' == 'Alice': %v\n", matched)

	// Contains match
	opts.Type = utils.ContainsMatch
	matched, _ = utils.Match("Hello World", "World", opts)
	fmt.Printf("Contains match 'Hello World' contains 'World': %v\n", matched)

	// Case insensitive match
	opts.Type = utils.Exact
	opts.CaseInsensitive = true
	matched, _ = utils.Match("Alice", "alice", opts)
	fmt.Printf("Case insensitive 'Alice' == 'alice': %v\n", matched)

	// Regex match
	opts.Type = utils.Regex
	opts.CaseInsensitive = false
	matched, _ = utils.Match("user123", "user\\d+", opts)
	fmt.Printf("Regex match 'user123' matches 'user\\d+': %v\n", matched)
	fmt.Println()

	// Example 3: FilterByFields with options
	fmt.Println("3. FilterByFields Examples:")
	filter := User{Name: "Alice", Active: true}
	opts = &utils.MatchOptions{Type: utils.Exact}

	filteredUsers := utils.FilterSlice(users, func(u User) bool {
		matched, _ := utils.FilterByFields(&filter, &u, opts,
			func(u *User) any { return u.Name },
			func(u *User) any { return u.Active })
		return matched
	})
	fmt.Printf("Users matching name='Alice' AND active=true: %+v\n", filteredUsers)

	// Case insensitive name filter
	opts.CaseInsensitive = true
	filter.Name = "alice"
	filteredUsers = utils.FilterSlice(users, func(u User) bool {
		matched, _ := utils.FilterByFields(&filter, &u, opts,
			func(u *User) any { return u.Name })
		return matched
	})
	fmt.Printf("Users matching name='alice' (case insensitive): %+v\n", filteredUsers)
	fmt.Println()

	// Example 4: Ordered field filtering
	fmt.Println("4. Ordered Field Filtering Examples:")
	// Filter users older than 28
	filteredUsers = utils.FilterSlice(users, func(u User) bool {
		return utils.FilterByOrderedField(&u, 28, utils.GreaterThan,
			func(u *User) int { return u.Age })
	})
	fmt.Printf("Users older than 28: %+v\n", filteredUsers)

	// Filter users with score >= 85
	filteredUsers = utils.FilterSlice(users, func(u User) bool {
		return utils.FilterByOrderedField(&u, 85.0, utils.GreaterThanOrEqual,
			func(u *User) float64 { return u.Score })
	})
	fmt.Printf("Users with score >= 85: %+v\n", filteredUsers)
	fmt.Println()

	// Example 5: String matching with different types
	fmt.Println("5. String Matching Examples:")
	opts = &utils.MatchOptions{Type: utils.StartsWith}
	filteredUsers = utils.FilterSlice(users, func(u User) bool {
		matched, _ := utils.Match(u.Name, "A", opts)
		return matched
	})
	fmt.Printf("Users whose name starts with 'A': %+v\n", filteredUsers)

	opts.Type = utils.EndsWith
	filteredUsers = utils.FilterSlice(users, func(u User) bool {
		matched, _ := utils.Match(u.Email, ".com", opts)
		return matched
	})
	fmt.Printf("Users whose email ends with '.com': %+v\n", filteredUsers)
	fmt.Println()

	// Example 6: JoinSlices
	fmt.Println("6. JoinSlices Example:")
	// Join users with products (simplified example)
	joinResult := utils.JoinSlices(users, products,
		func(u User, p Product) bool { return u.ID == p.ID },
		func(u User, p Product) string { return fmt.Sprintf("%s owns %s", u.Name, p.Name) })
	fmt.Printf("User-Product joins: %+v\n", joinResult)
	fmt.Println()

	// Example 7: FilterSlice and FindFirst
	fmt.Println("7. FilterSlice and FindFirst Examples:")
	// Filter active users
	activeUsers := utils.FilterSlice(users, func(u User) bool { return u.Active })
	fmt.Printf("Active users: %+v\n", activeUsers)

	// Find first user with age > 30
	if user, found := utils.FindFirst(users, func(u User) bool { return u.Age > 30 }); found {
		fmt.Printf("First user older than 30: %+v\n", user)
	}
	fmt.Println()

	// Example 8: Complex filtering with multiple conditions
	fmt.Println("8. Complex Filtering Example:")
	complexFiltered := utils.FilterSlice(users, func(u User) bool {
		// Age between 25-35 AND score > 80 AND name contains 'i'
		ageMatch := utils.FilterByOrderedField(&u, 25, utils.GreaterThanOrEqual,
			func(u *User) int { return u.Age }) &&
			utils.FilterByOrderedField(&u, 35, utils.LessThanOrEqual,
				func(u *User) int { return u.Age })

		scoreMatch := utils.FilterByOrderedField(&u, 80.0, utils.GreaterThan,
			func(u *User) float64 { return u.Score })

		nameMatch, _ := utils.Match(u.Name, "i", &utils.MatchOptions{Type: utils.ContainsMatch})

		return ageMatch && scoreMatch && nameMatch
	})
	fmt.Printf("Users aged 25-35 with score > 80 and name containing 'i': %+v\n", complexFiltered)
}
