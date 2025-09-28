package main

import (
	"context"
	"fmt"

	"github.com/oarkflow/cas"
)

func main() {
	fmt.Println("=== Role Hierarchy Example ===")

	// Create authorizer
	auth := cas.NewAuthorizer(cas.WithDefaultDeny(true))

	// Create roles with hierarchy
	superAdmin := cas.NewRole("super_admin")
	superAdmin.AddPermission(&cas.Permission{Resource: "*", Action: "*"})

	admin := cas.NewRole("admin")
	admin.AddPermission(&cas.Permission{Resource: "users/*", Action: "read"})
	admin.AddPermission(&cas.Permission{Resource: "users/*", Action: "write"})
	admin.AddPermission(&cas.Permission{Resource: "settings/*", Action: "read"})

	manager := cas.NewRole("manager")
	manager.AddPermission(&cas.Permission{Resource: "users/*", Action: "read"})
	manager.AddPermission(&cas.Permission{Resource: "reports/*", Action: "read"})

	user := cas.NewRole("user")
	user.AddPermission(&cas.Permission{Resource: "users/profile", Action: "read"})

	// Add roles
	auth.AddRole(superAdmin)
	auth.AddRole(admin)
	auth.AddRole(manager)
	auth.AddRole(user)

	// Establish hierarchy: super_admin > admin > manager > user
	auth.AddChildRole("super_admin", "admin")
	auth.AddChildRole("admin", "manager")
	auth.AddChildRole("manager", "user")

	// Create tenant
	tenant := cas.NewTenant("company1", "default")
	auth.AddTenant(tenant)

	// Assign roles
	auth.AddPrincipalRole(&cas.PrincipalRole{Principal: "alice", Tenant: "company1", Role: "super_admin"})
	auth.AddPrincipalRole(&cas.PrincipalRole{Principal: "bob", Tenant: "company1", Role: "admin"})
	auth.AddPrincipalRole(&cas.PrincipalRole{Principal: "charlie", Tenant: "company1", Role: "manager"})
	auth.AddPrincipalRole(&cas.PrincipalRole{Principal: "dave", Tenant: "company1", Role: "user"})

	// Test inherited permissions
	testCases := []struct {
		label    string
		request  cas.Request
		expected bool
	}{
		{"Super admin can do anything", cas.Request{Principal: "alice", Tenant: "company1", Resource: "system/config", Action: "delete"}, true},
		{"Admin inherits user permissions", cas.Request{Principal: "bob", Tenant: "company1", Resource: "users/profile", Action: "read"}, true},
		{"Manager inherits user permissions", cas.Request{Principal: "charlie", Tenant: "company1", Resource: "users/profile", Action: "read"}, true},
		{"Manager can access reports", cas.Request{Principal: "charlie", Tenant: "company1", Resource: "reports/sales", Action: "read"}, true},
		{"Admin can access settings", cas.Request{Principal: "bob", Tenant: "company1", Resource: "settings/app", Action: "read"}, true},
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
