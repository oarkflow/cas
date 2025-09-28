package main

import (
	"context"
	"fmt"

	"github.com/oarkflow/cas"
)

func main() {
	fmt.Println("=== Basic RBAC Example ===")

	// Create authorizer
	auth := cas.NewAuthorizer()

	// Create roles
	adminRole := cas.NewRole("admin")
	adminRole.AddPermission(&cas.Permission{Resource: "users/*", Action: "read"})
	adminRole.AddPermission(&cas.Permission{Resource: "users/*", Action: "write"})

	userRole := cas.NewRole("user")
	userRole.AddPermission(&cas.Permission{Resource: "users/profile", Action: "read"})

	// Add roles to authorizer
	auth.AddRole(adminRole)
	auth.AddRole(userRole)

	// Create tenant
	tenant := cas.NewTenant("company1", "default")
	auth.AddTenant(tenant)

	// Assign roles to users
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

	// Test authorizations
	testCases := []struct {
		label    string
		request  cas.Request
		expected bool
	}{
		{"Admin can read all users", cas.Request{Principal: "alice", Tenant: "company1", Resource: "users/list", Action: "read"}, true},
		{"Admin can write users", cas.Request{Principal: "alice", Tenant: "company1", Resource: "users/123", Action: "write"}, true},
		{"User can read own profile", cas.Request{Principal: "bob", Tenant: "company1", Resource: "users/profile", Action: "read"}, true},
		{"User cannot write users", cas.Request{Principal: "bob", Tenant: "company1", Resource: "users/123", Action: "write"}, false},
		{"Unknown user denied", cas.Request{Principal: "charlie", Tenant: "company1", Resource: "users/profile", Action: "read"}, false},
	}

	for _, tc := range testCases {
		result := auth.Authorize(context.Background(), tc.request)
		status := "✓"
		if result != tc.expected {
			status = "✗"
		}
		fmt.Printf("%s %s: %v (expected %v)\n", status, tc.label, result, tc.expected)
	}
}
