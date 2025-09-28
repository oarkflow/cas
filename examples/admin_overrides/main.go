package main

import (
	"context"
	"fmt"

	"github.com/oarkflow/cas"
)

func main() {
	fmt.Println("=== Admin Overrides Example ===")

	auth := cas.NewAuthorizer()

	// Setup basic data
	userRole := cas.NewRole("user")
	userRole.AddPermission(&cas.Permission{Resource: "users/profile", Action: "read"})
	auth.AddRole(userRole)

	tenant := cas.NewTenant("company1", "default")
	auth.AddTenant(tenant)

	auth.AddPrincipalRole(&cas.PrincipalRole{
		Principal: "alice",
		Tenant:    "company1",
		Role:      "user",
	})

	// Normal authorization (should deny)
	request := cas.Request{
		Principal: "alice",
		Tenant:    "company1",
		Resource:  "admin/panel",
		Action:    "access",
	}

	fmt.Println("Normal authorization:")
	result := auth.Authorize(context.Background(), request)
	fmt.Printf("Result: %v (expected: false)\n", result)

	// Force allow
	fmt.Println("\nForce allow:")
	result = auth.ForceAllow(request)
	fmt.Printf("Result: %v (expected: true)\n", result)

	// Force deny (even if normally allowed)
	request2 := cas.Request{
		Principal: "alice",
		Tenant:    "company1",
		Resource:  "users/profile",
		Action:    "read",
	}

	fmt.Println("\nNormal authorization for allowed action:")
	result = auth.Authorize(context.Background(), request2)
	fmt.Printf("Result: %v (expected: true)\n", result)

	fmt.Println("\nForce deny for allowed action:")
	result = auth.ForceDeny(request2)
	fmt.Printf("Result: %v (expected: false)\n", result)

	fmt.Println("Admin overrides example completed.")
}
