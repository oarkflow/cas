package main

import (
	"encoding/json"
	"fmt"
	"os"
	
	"github.com/oarkflow/cas"
)

// JSONFileStorage implements cas.Storage using JSON files for each entity type.
type JSONFileStorage struct {
	RolesFile       string
	TenantsFile     string
	PermissionsFile string
	AssignmentsFile string
	NamespacesFile  string
	ScopesFile      string
}

func loadJSONFile[T any](filename string) ([]T, error) {
	if filename == "" {
		return nil, nil
	}
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var data []T
	if err := json.NewDecoder(f).Decode(&data); err != nil {
		return nil, err
	}
	return data, nil
}

func (s *JSONFileStorage) LoadRoles() ([]*cas.Role, error) {
	return loadJSONFile[*cas.Role](s.RolesFile)
}
func (s *JSONFileStorage) LoadTenants() ([]*cas.Tenant, error) {
	return loadJSONFile[*cas.Tenant](s.TenantsFile)
}
func (s *JSONFileStorage) LoadPermissions() ([]*cas.Permission, error) {
	return loadJSONFile[*cas.Permission](s.PermissionsFile)
}
func (s *JSONFileStorage) LoadAssignments() ([]*cas.PrincipalRole, error) {
	return loadJSONFile[*cas.PrincipalRole](s.AssignmentsFile)
}
func (s *JSONFileStorage) LoadNamespaces() ([]*cas.Namespace, error) {
	return loadJSONFile[*cas.Namespace](s.NamespacesFile)
}
func (s *JSONFileStorage) LoadScopes() ([]*cas.Scope, error) {
	return loadJSONFile[*cas.Scope](s.ScopesFile)
}

func main() {
	// Example: Use JSON files as storage backend
	storage := &JSONFileStorage{
		RolesFile:       "roles.json",
		TenantsFile:     "tenants.json",
		PermissionsFile: "permissions.json",
		AssignmentsFile: "assignments.json",
		NamespacesFile:  "namespaces.json",
		ScopesFile:      "scopes.json",
	}
	
	authorizer := cas.NewAuthorizer(
		cas.WithStorage(storage),
		cas.WithEntityLoadOrder([]cas.EntityType{
			cas.EntityRoles,
			cas.EntityTenants,
			cas.EntityNamespaces,
			cas.EntityScopes,
			cas.EntityPermissions,
			cas.EntityAssignments,
		}),
	)
	
	// Load all entities from JSON files
	if err := authorizer.LoadEntities(); err != nil {
		fmt.Println("Failed to load entities:", err)
		return
	}
	
	// Register ABAC hooks as before
	authorizer.RegisterABAC("checkPrincipal", func(req cas.Request, attrs map[string]any) (bool, error) {
		if attrs == nil {
			return req.Principal == "21890", nil
		}
		return true, nil
	})
	
	authorizer.RegisterABAC("checkBusinessHour", func(req cas.Request, attrs map[string]any) (bool, error) {
		if attrs == nil {
			hour := 10 // simulate time.Now().Hour()
			if hour < 9 || hour > 17 {
				return false, nil
			}
			return true, nil
		}
		return true, nil
	})
	
	fmt.Println("== ABAC Only (no attributes) ==")
	request := cas.Request{
		Principal: "21890",
		Tenant:    "1",
	}
	authorized := authorizer.Authorize(request)
	fmt.Println("Authorize (should be true):", authorized)
	
	requestFail := cas.Request{
		Principal: "99999",
		Tenant:    "1",
	}
	authorizedFail := authorizer.Authorize(requestFail)
	fmt.Println("Authorize (should be false):", authorizedFail)
	
	authorizer.RegisterABAC("checkOwner", func(req cas.Request, attrs map[string]any) (bool, error) {
		if attrs != nil {
			if attrs["owner_id"] == req.Principal {
				return true, nil
			}
			return false, nil
		}
		return true, nil
	})
	
	fmt.Println("\n== ABAC with Attributes ==")
	attrReq := cas.Request{
		Principal:  "21890",
		Tenant:     "1",
		Resource:   "/resource/123",
		Action:     "read",
		Attributes: map[string]any{"owner_id": "21890"},
	}
	authorizedWithAttrs := authorizer.Authorize(attrReq)
	fmt.Println("AuthorizeWithAttributes (owner match, should be true):", authorizedWithAttrs)
	
	attrReqNotOwner := cas.Request{
		Principal:  "21890",
		Tenant:     "1",
		Resource:   "/resource/123",
		Action:     "read",
		Attributes: map[string]any{"owner_id": "99999"},
	}
	authorizedWithAttrsFail := authorizer.Authorize(attrReqNotOwner)
	fmt.Println("AuthorizeWithAttributes (owner mismatch, should be false):", authorizedWithAttrsFail)
	
	authorizedWithAttrsNone := authorizer.Authorize(attrReq)
	fmt.Println("AuthorizeWithAttributes (no attributes, should be true):", authorizedWithAttrsNone)
	
	attrReqNoPrincipal := cas.Request{
		Principal:  "",
		Tenant:     "1",
		Resource:   "/resource/123",
		Action:     "read",
		Attributes: map[string]any{"owner_id": "21890"},
	}
	authorizedWithAttrsNoPrincipal := authorizer.Authorize(attrReqNoPrincipal)
	fmt.Println("AuthorizeWithAttributes (no principal, should be false):", authorizedWithAttrsNoPrincipal)
}

func SimulateAuthorization(authorizer *cas.Authorizer, request cas.Request) {
	fmt.Println("Simulating authorization...")
	authorized := authorizer.Authorize(request)
	fmt.Printf("Simulation result: %v\n", authorized)
}
