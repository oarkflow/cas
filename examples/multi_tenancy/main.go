package main

import (
	"context"
	"fmt"

	"github.com/oarkflow/cas"
)

func main() {
	fmt.Println("=== Multi-Tenancy Example ===")

	auth := cas.NewAuthorizer()

	// Create roles
	adminRole := cas.NewRole("admin")
	adminRole.AddPermission(&cas.Permission{Resource: "users/*", Action: "read"})
	adminRole.AddPermission(&cas.Permission{Resource: "users/*", Action: "write"})

	userRole := cas.NewRole("user")
	userRole.AddPermission(&cas.Permission{Resource: "users/profile", Action: "read"})

	auth.AddRole(adminRole)
	auth.AddRole(userRole)

	// Create tenants with namespaces and scopes
	tenant1 := cas.NewTenant("company1")
	tenant1.AddNamespace("hr", true)
	tenant1.AddNamespace("finance")
	tenant1.AddScopeToNamespace("hr", cas.NewScope("employees"))
	tenant1.AddScopeToNamespace("hr", cas.NewScope("managers"))
	tenant1.AddScopeToNamespace("finance", cas.NewScope("budgets"))

	tenant2 := cas.NewTenant("company2")
	tenant2.AddNamespace("sales", true)
	tenant2.AddScopeToNamespace("sales", cas.NewScope("leads"))
	tenant2.AddScopeToNamespace("sales", cas.NewScope("deals"))

	// Create hierarchical tenants
	parentTenant := cas.NewTenant("parent")
	childTenant := cas.NewTenant("child")
	parentTenant.AddChildTenantWithInheritance(childTenant, true)

	auth.AddTenant(tenant1)
	auth.AddTenant(tenant2)
	auth.AddTenant(parentTenant)

	// Assign roles with different scopes
	auth.AddPrincipalRole(&cas.PrincipalRole{
		Principal: "alice",
		Tenant:    "company1",
		Namespace: "hr",
		Scope:     "managers",
		Role:      "admin",
	})
	auth.AddPrincipalRole(&cas.PrincipalRole{
		Principal: "bob",
		Tenant:    "company1",
		Namespace: "hr",
		Scope:     "employees",
		Role:      "user",
	})
	auth.AddPrincipalRole(&cas.PrincipalRole{
		Principal: "charlie",
		Tenant:    "company2",
		Namespace: "sales",
		Role:      "admin",
	})
	auth.AddPrincipalRole(&cas.PrincipalRole{
		Principal: "dave",
		Tenant:    "parent",
		Role:      "admin",
	})

	// Test multi-tenant authorizations
	testCases := []struct {
		label    string
		request  cas.Request
		expected bool
	}{
		{"Alice can manage HR in company1", cas.Request{Principal: "alice", Tenant: "company1", Namespace: "hr", Scope: "managers", Resource: "users/list", Action: "read"}, true},
		{"Bob can read profile in HR employees scope", cas.Request{Principal: "bob", Tenant: "company1", Namespace: "hr", Scope: "employees", Resource: "users/profile", Action: "read"}, true},
		{"Charlie can manage sales in company2", cas.Request{Principal: "charlie", Tenant: "company2", Namespace: "sales", Resource: "users/list", Action: "write"}, true},
		{"Dave inherits permissions in child tenant", cas.Request{Principal: "dave", Tenant: "child", Resource: "users/list", Action: "read"}, true},
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
