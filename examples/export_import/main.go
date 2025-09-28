package main

import (
	"context"
	"fmt"

	"github.com/oarkflow/cas"
)

func main() {
	fmt.Println("=== Export/Import Example ===")

	// Create authorizer with data
	auth := cas.NewAuthorizer()

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

	// Export policies
	fmt.Println("Exporting policies...")
	data, err := auth.ExportPolicies()
	if err != nil {
		fmt.Printf("Export failed: %v\n", err)
		return
	}
	fmt.Printf("Exported %d bytes of policy data\n", len(data))

	// Create new authorizer and import
	fmt.Println("Importing policies into new authorizer...")
	auth2 := cas.NewAuthorizer()
	if err := auth2.ImportPolicies(data); err != nil {
		fmt.Printf("Import failed: %v\n", err)
		return
	}

	// Test imported data
	request := cas.Request{
		Principal: "alice",
		Tenant:    "company1",
		Resource:  "users/list",
		Action:    "read",
	}
	result := auth2.Authorize(context.Background(), request)
	fmt.Printf("Authorization after import: %v (expected: true)\n", result)

	fmt.Println("Export/Import example completed.")
}
