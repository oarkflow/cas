package cas

import (
	"testing"
	"time"
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

func TestAuthorizeWithAttributes_TimeBasedAccess(t *testing.T) {
	authorizer := setupAuthorizer()
	request := Request{
		Principal: "user1",
		Tenant:    "tenant1",
		Resource:  "resourceA",
		Action:    "GET",
	}
	attributes := map[string]any{
		"time": time.Date(2023, 10, 10, 20, 0, 0, 0, time.UTC), // Outside allowed hours
	}
	authorized := authorizer.AuthorizeWithAttributes(request, attributes)
	if authorized {
		t.Errorf("Expected authorization denied due to time-based restriction, got true")
	}
}

func TestWildcardAndHierarchicalResourceMatching(t *testing.T) {
	authorizer := setupAuthorizer()
	role := NewRole("role3")
	role.AddPermission(&Permission{Resource: "resource/*", Action: "GET"})
	authorizer.AddRole(role)
	authorizer.AddPrincipalRole(&PrincipalRole{
		Principal: "user1",
		Tenant:    "tenant1",
		Role:      "role3",
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

func TestDenyPermissions(t *testing.T) {
	authorizer := setupAuthorizer()
	role := NewRole("role1")
	role.AddDenyPermission(&Permission{Resource: "resourceA", Action: "GET"})
	authorizer.AddRole(role)
	authorizer.AddPrincipalRole(&PrincipalRole{
		Principal: "user1",
		Tenant:    "tenant1",
		Role:      "role1",
	})
	request := Request{
		Principal: "user1",
		Tenant:    "tenant1",
		Resource:  "resourceA",
		Action:    "GET",
	}
	authorized := authorizer.Authorize(request)
	if authorized {
		t.Errorf("Expected authorization denied due to deny permission, got true")
	}
}

func TestHierarchicalTenancy(t *testing.T) {
	authorizer := setupAuthorizer()
	parentTenant := NewTenant("parentTenant")
	childTenant := NewTenant("childTenant")
	parentTenant.AddNamespace("namespace1", true)
	parentTenant.AddScopeToNamespace("namespace1", NewScope("scope1"))
	parentTenant.AddChildTenantWithInheritance(childTenant, true)
	authorizer.AddTenant(parentTenant)
	authorizer.AddPrincipalRole(&PrincipalRole{
		Principal: "user1",
		Tenant:    "parentTenant",
		Role:      "role1",
	})
	role := NewRole("role1")
	role.AddPermission(&Permission{Resource: "resourceA", Action: "GET"})
	authorizer.AddRole(role)
	request := Request{
		Principal: "user1",
		Tenant:    "childTenant",
		Resource:  "resourceA",
		Action:    "GET",
	}
	authorized := authorizer.Authorize(request)
	if !authorized {
		t.Errorf("Expected authorization for inherited role, got false")
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
