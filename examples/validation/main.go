package main

import (
	"fmt"

	"github.com/oarkflow/cas"
)

func main() {
	fmt.Println("=== Validation Example ===")

	auth := cas.NewAuthorizer()

	// Setup valid data
	adminRole := cas.NewRole("admin")
	adminRole.AddPermission(&cas.Permission{Resource: "users/*", Action: "read"})
	auth.AddRole(adminRole)

	userRole := cas.NewRole("user")
	userRole.AddPermission(&cas.Permission{Resource: "users/profile", Action: "read"})
	auth.AddRole(userRole)

	// Create circular dependency (invalid)
	auth.AddChildRole("admin", "user")
	auth.AddChildRole("user", "admin") // This creates a cycle

	tenant := cas.NewTenant("company1", "default")
	auth.AddTenant(tenant)

	// Add invalid principal role (empty principal)
	auth.AddPrincipalRole(&cas.PrincipalRole{
		Principal: "", // Invalid
		Tenant:    "company1",
		Role:      "admin",
	})

	// Validate
	fmt.Println("Validating authorizer configuration...")
	if err := auth.Validate(); err != nil {
		fmt.Printf("Validation failed as expected: %v\n", err)
	} else {
		fmt.Println("Validation passed (unexpected)")
	}

	// Fix the issues
	fmt.Println("\nFixing issues...")
	auth.RemovePrincipalRole(cas.PrincipalRole{Principal: "", Tenant: "company1", Role: "admin"})

	// Remove circular dependency by recreating roles
	auth = cas.NewAuthorizer()
	auth.AddRole(adminRole)
	auth.AddRole(userRole)
	auth.AddChildRole("admin", "user") // Only one direction
	auth.AddTenant(tenant)
	auth.AddPrincipalRole(&cas.PrincipalRole{
		Principal: "alice",
		Tenant:    "company1",
		Role:      "admin",
	})

	// Validate again
	if err := auth.Validate(); err != nil {
		fmt.Printf("Validation still failed: %v\n", err)
	} else {
		fmt.Println("Validation passed!")
	}
}
