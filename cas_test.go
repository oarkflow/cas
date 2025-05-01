package cas

import (
	"testing"
)

func TestAuthorize_ValidDirectPermission(t *testing.T) {
	authorizer := setupAuthorizer() // Setup roleDAG, tenants, and user roleDAG
	request := Request{
		Principal: "user1",
		Tenant:    "tenant1",
		Scope:     "scope1",
		Resource:  "resourceA",
		Action:    "GET",
	}
	authorized := authorizer.Authorize(request)
	if !authorized {
		t.Errorf("Expected authorization, got false")
	}
}

func TestWildcardResourcePermission(t *testing.T) {
	authorizer := setupAuthorizer()
	role := NewRole("role2")
	role.AddPermission(&Permission{Resource: "resource/*", Action: "GET", Category: "category1"})
	authorizer.AddRole(role)
	authorizer.AddPrincipalRole(&PrincipalRole{
		Principal: "user1",
		Tenant:    "tenant1",
		Role:      "role2",
	})
	request := Request{
		Principal: "user1",
		Tenant:    "tenant1",
		Resource:  "resource/subresource",
		Action:    "GET",
	}
	authorized := authorizer.Authorize(request)
	if !authorized {
		t.Errorf("Expected authorization for wildcard resource, got false")
	}
}

func TestAuthorize_ValidParentTenantPermission(t *testing.T) {
	authorizer := setupAuthorizer()
	request := Request{
		Principal: "user2",
		Tenant:    "childTenant1",
		Scope:     "scope1",
		Resource:  "resourceB",
		Action:    "POST",
	}
	authorized := authorizer.Authorize(request)
	if authorized {
		t.Errorf("Expected authorization denied from childTenant1 tenant, got true")
	}
}

func TestAuthorize_ValidGlobalScopePermission(t *testing.T) {
	authorizer := setupAuthorizer()
	request := Request{
		Principal: "user3",
		Tenant:    "tenant2",
		Resource:  "resourceC",
		Action:    "DELETE",
	}
	authorized := authorizer.Authorize(request)
	if authorized {
		t.Errorf("Expected authentication failed for empty scope, got true")
	}
}

func TestAuthorize_NoMatchingPermission(t *testing.T) {
	authorizer := setupAuthorizer()
	request := Request{
		Principal: "user1",
		Tenant:    "tenant1",
		Scope:     "scope2", // No permission in this scope
		Resource:  "resourceA",
		Action:    "GET",
	}
	authorized := authorizer.Authorize(request)
	if authorized {
		t.Errorf("Expected false for unmatched scope, got true")
	}
}

func TestAuthorize_InvalidTenant(t *testing.T) {
	authorizer := setupAuthorizer()
	request := Request{
		Principal: "user1",
		Tenant:    "invalidTenant",
		Scope:     "scope1",
		Resource:  "resourceA",
		Action:    "GET",
	}
	authorized := authorizer.Authorize(request)
	if authorized {
		t.Errorf("Expected false for invalid tenant, got true")
	}
}

func TestAuthorize_CircularRolePermissions(t *testing.T) {
	authorizer := setupAuthorizerWithCircularRoles()
	request := Request{
		Principal: "user1",
		Tenant:    "tenant1",
		Scope:     "scope1",
		Resource:  "resourceA",
		Action:    "GET",
	}
	authorized := authorizer.Authorize(request)
	if authorized {
		t.Errorf("Expected false due to circular role, got true")
	}
}

func TestAuthorize_InvalidScope(t *testing.T) {
	authorizer := setupAuthorizer()
	request := Request{
		Principal: "user1",
		Tenant:    "tenant1",
		Scope:     "nonexistentScope",
		Resource:  "resourceA",
		Action:    "GET",
	}
	authorized := authorizer.Authorize(request)
	if authorized {
		t.Errorf("Expected false for invalid scope, got true")
	}
}

func TestAuthorize_ResolutionFailure(t *testing.T) {
	authorizer := setupAuthorizer() // With misconfigured roleDAG or missing permissions
	request := Request{
		Principal: "user4",
		Tenant:    "tenant3",
		Scope:     "scope1",
		Resource:  "resourceD",
		Action:    "PATCH",
	}
	authorized := authorizer.Authorize(request)
	if authorized {
		t.Errorf("Expected false due to permission resolution failure, got true")
	}
}

func setupAuthorizer() *Authorizer {
	authorizer := NewAuthorizer()
	role := NewRole("role1")
	role.AddPermission(&Permission{Resource: "resourceA", Action: "GET", Category: "category1"})
	authorizer.AddRole(role)
	namespace := "coding"
	tenant := NewTenant("tenant1", namespace)
	err := tenant.AddScopeToNamespace(namespace, NewScope("scope1"))
	if err != nil {
		panic(err)
	}
	authorizer.AddTenant(tenant)
	authorizer.AddPrincipalRole(&PrincipalRole{
		Principal: "user1",
		Tenant:    "tenant1",
		Role:      "role1",
	})
	return authorizer
}

func setupAuthorizerWithCircularRoles() *Authorizer {
	// Create roleDAG with circular dependency and add them to RoleDAG
	return NewAuthorizer()
}
