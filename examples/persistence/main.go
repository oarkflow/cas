package main

import (
	"context"
	"fmt"
	"os"

	"github.com/oarkflow/cas"
	"github.com/oarkflow/cas/storage"
)

func main() {
	fmt.Println("=== Persistence Example ===")

	// Create authorizer with file storage
	store := &storage.FileStorage{
		RoleFile:       "temp_roles.json",
		TenantFile:     "temp_tenants.json",
		PermissionFile: "temp_permissions.json",
		AssignmentFile: "temp_assignments.json",
		NamespaceFile:  "temp_namespaces.json",
		ScopeFile:      "temp_scopes.json",
	}
	auth := cas.NewAuthorizer(cas.WithStorage(store))

	// Setup initial data
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

	// Save entities
	fmt.Println("Saving entities...")
	if err := auth.SaveEntities(); err != nil {
		fmt.Printf("Error saving: %v\n", err)
		return
	}

	// Create new authorizer and load
	fmt.Println("Loading entities into new authorizer...")
	auth2 := cas.NewAuthorizer(cas.WithStorage(store))
	if err := auth2.LoadEntities(); err != nil {
		fmt.Printf("Error loading: %v\n", err)
		return
	}

	// Test that loaded data works
	request := cas.Request{
		Principal: "alice",
		Tenant:    "company1",
		Resource:  "users/list",
		Action:    "read",
	}
	result := auth2.Authorize(context.Background(), request)
	fmt.Printf("Authorization after load: %v (expected: true)\n", result)

	// Cleanup
	os.Remove("temp_roles.json")
	os.Remove("temp_tenants.json")
	os.Remove("temp_permissions.json")
	os.Remove("temp_assignments.json")
	os.Remove("temp_namespaces.json")
	os.Remove("temp_scopes.json")

	fmt.Println("Persistence example completed.")
}
