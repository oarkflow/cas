package main

import (
	"context"
	"fmt"

	"github.com/oarkflow/cas"
)

func main() {
	fmt.Println("=== Metrics Example ===")

	auth := cas.NewAuthorizer()

	// Setup basic data
	adminRole := cas.NewRole("admin")
	adminRole.AddPermission(&cas.Permission{Resource: "users/*", Action: "read"})
	auth.AddRole(adminRole)

	tenant := cas.NewTenant("company1", "default")
	auth.AddTenant(tenant)

	auth.AddPrincipalRole(&cas.PrincipalRole{
		Principal: "alice",
		Tenant:    "company1",
		Role:      "admin",
	})

	// Perform some authorizations to generate metrics
	fmt.Println("Performing authorization requests...")
	requests := []cas.Request{
		{Principal: "alice", Tenant: "company1", Resource: "users/list", Action: "read"},
		{Principal: "alice", Tenant: "company1", Resource: "users/123", Action: "write"}, // Should deny
		{Principal: "bob", Tenant: "company1", Resource: "users/list", Action: "read"},   // Should deny
		{Principal: "alice", Tenant: "company1", Resource: "users/profile", Action: "read"},
	}

	for i, req := range requests {
		result := auth.Authorize(context.Background(), req)
		fmt.Printf("Request %d: %v\n", i+1, result)
	}

	// Display metrics
	fmt.Println("\nMetrics:")
	auth.LogMetrics()

	fmt.Println("Metrics example completed.")
}
