package main

import (
	"context"
	"fmt"
	"time"

	"github.com/oarkflow/cas"
)

func main() {
	fmt.Println("=== Advanced Permissions Example ===")

	auth := cas.NewAuthorizer()

	// Create roles with various permission types
	adminRole := cas.NewRole("admin")
	adminRole.AddPermission(&cas.Permission{Resource: "*", Action: "*"}) // Wildcard

	userRole := cas.NewRole("user")
	userRole.AddPermission(&cas.Permission{Resource: "users/profile", Action: "read"})
	userRole.AddPermission(&cas.Permission{Resource: "posts/:id", Action: "read"}) // Parameter

	guestRole := cas.NewRole("guest")
	guestRole.AddPermission(&cas.Permission{Resource: "public/*", Action: "read"})
	guestRole.AddDenyPermission(&cas.Permission{Resource: "public/admin", Action: "read"}) // Explicit deny

	auth.AddRole(adminRole)
	auth.AddRole(userRole)
	auth.AddRole(guestRole)

	tenant := cas.NewTenant("company1", "default")
	auth.AddTenant(tenant)

	// Assign roles with expiry
	auth.AddPrincipalRole(&cas.PrincipalRole{
		Principal: "alice",
		Tenant:    "company1",
		Role:      "admin",
	})

	auth.AddPrincipalRole(&cas.PrincipalRole{
		Principal: "bob",
		Tenant:    "company1",
		Role:      "user",
	})

	auth.AddPrincipalRole(&cas.PrincipalRole{
		Principal: "charlie",
		Tenant:    "company1",
		Role:      "guest",
	})

	// Test wildcard permissions
	fmt.Println("Testing wildcard permissions:")
	testCases := []struct {
		label    string
		request  cas.Request
		expected bool
	}{
		{"Admin wildcard access", cas.Request{Principal: "alice", Tenant: "company1", Resource: "any/resource", Action: "any"}, true},
		{"User parameter matching", cas.Request{Principal: "bob", Tenant: "company1", Resource: "posts/123", Action: "read"}, true},
		{"User parameter no match", cas.Request{Principal: "bob", Tenant: "company1", Resource: "posts/123", Action: "write"}, false},
		{"Guest public access", cas.Request{Principal: "charlie", Tenant: "company1", Resource: "public/news", Action: "read"}, true},
		{"Guest denied admin public", cas.Request{Principal: "charlie", Tenant: "company1", Resource: "public/admin", Action: "read"}, false},
	}

	for _, tc := range testCases {
		result := auth.Authorize(context.Background(), tc.request)
		status := "✓"
		if result != tc.expected {
			status = "✗"
		}
		fmt.Printf("%s %s: %v (expected %v)\n", status, tc.label, result, tc.expected)
	}

	// Test expiry
	fmt.Println("\nTesting role expiry:")
	expiryRole := cas.NewRole("temp")
	expiryRole.AddPermission(&cas.Permission{Resource: "temp/*", Action: "read"})
	auth.AddRole(expiryRole)

	// Add role with short expiry
	pr := &cas.PrincipalRole{
		Principal: "temp_user",
		Tenant:    "company1",
		Role:      "temp",
	}
	pr.SetExpiryDuration("2s", auth.Clock())
	auth.AddPrincipalRole(pr)

	// Test before expiry
	request := cas.Request{Principal: "temp_user", Tenant: "company1", Resource: "temp/data", Action: "read"}
	result := auth.Authorize(context.Background(), request)
	fmt.Printf("Before expiry: %v (expected: true)\n", result)

	// Wait for expiry
	fmt.Println("Waiting for expiry...")
	time.Sleep(3 * time.Second)

	// Clean expired roles
	auth.CleanExpiredPrincipalRoles()

	// Test after expiry
	result = auth.Authorize(context.Background(), request)
	fmt.Printf("After expiry: %v (expected: false)\n", result)

	fmt.Println("Advanced permissions example completed.")
}
