package cas

import (
	"fmt"
	"sync"
)

func (p *Permission) String() string {
	return p.Resource + " " + p.Action
}

func (r *Role) AddPermission(permissions ...*Permission) {
	r.m.Lock()
	defer r.m.Unlock()
	for _, permission := range permissions {
		r.Permissions[permission.String()] = struct{}{}
	}
}

func (r *Role) RemovePermission(permissions ...*Permission) {
	r.m.Lock()
	defer r.m.Unlock()
	for _, permission := range permissions {
		delete(r.Permissions, permission.String())
	}
}

func (t *Tenant) AddNamespace(namespace string, isDefault ...bool) {
	t.m.Lock()
	defer t.m.Unlock()
	if _, exists := t.Namespaces[namespace]; !exists {
		t.Namespaces[namespace] = NewNamespace(namespace)
	}
	if len(isDefault) > 0 && isDefault[0] {
		t.DefaultNS = namespace
	}
}

func (t *Tenant) AddScopeToNamespace(namespace string, scopes ...*Scope) error {
	t.m.Lock()
	defer t.m.Unlock()
	ns, exists := t.Namespaces[namespace]
	if !exists {
		return fmt.Errorf("namespace %s does not exist in tenant %s", namespace, t.ID)
	}
	for _, scope := range scopes {
		ns.Scopes[scope.ID] = scope
	}
	t.Namespaces[namespace] = ns
	return nil
}

func (t *Tenant) AddChildTenant(tenants ...*Tenant) {
	t.m.Lock()
	defer t.m.Unlock()
	for _, tenant := range tenants {
		t.ChildTenants[tenant.ID] = tenant
	}
}

type RoleDAG struct {
	mu            sync.RWMutex
	roles         map[string]*Role
	edges         map[string][]string
	resolved      map[string]map[string]struct{} // cache for permissions
	resolvedRoles map[string]map[string]struct{} // new cache for child roles
}

func NewRoleDAG() *RoleDAG {
	return &RoleDAG{
		roles:         make(map[string]*Role),
		edges:         make(map[string][]string),
		resolved:      make(map[string]map[string]struct{}),
		resolvedRoles: make(map[string]map[string]struct{}),
	}
}

func (dag *RoleDAG) AddRole(roles ...*Role) {
	dag.mu.Lock()
	defer dag.mu.Unlock()
	for _, role := range roles {
		dag.roles[role.Name] = role
	}
	// Clear caches since roles changed.
	dag.resolved = make(map[string]map[string]struct{})
	dag.resolvedRoles = make(map[string]map[string]struct{})
}

func (dag *RoleDAG) AddChildRole(parent string, child ...string) error {
	dag.mu.Lock()
	defer dag.mu.Unlock()
	if err := dag.checkCircularDependency(parent, child...); err != nil {
		return err
	}
	dag.edges[parent] = append(dag.edges[parent], child...)
	// Clear caches since role graph changed.
	dag.resolved = make(map[string]map[string]struct{})
	dag.resolvedRoles = make(map[string]map[string]struct{})
	return nil
}

func (dag *RoleDAG) checkCircularDependency(parent string, children ...string) error {
	visited := map[string]bool{parent: true}
	var dfs func(string) bool
	dfs = func(role string) bool {
		if visited[role] {
			return true
		}
		visited[role] = true
		for _, child := range dag.edges[role] {
			if dfs(child) {
				return true
			}
		}
		return false
	}
	for _, child := range children {
		if dfs(child) {
			return fmt.Errorf("circular role dependency detected: %s -> %s", parent, child)
		}
	}
	return nil
}

// ResolvePermissions to account for role expiry
func (dag *RoleDAG) ResolvePermissions(roleName string) map[string]struct{} {
	dag.mu.RLock()
	if permissions, found := dag.resolved[roleName]; found {
		dag.mu.RUnlock()
		return permissions
	}
	dag.mu.RUnlock()
	dag.mu.Lock()
	defer dag.mu.Unlock()
	visited := make(map[string]bool)
	queue := []string{roleName}
	result := make(map[string]struct{})
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if visited[current] {
			continue
		}
		visited[current] = true
		role, exists := dag.roles[current]
		if !exists {
			continue
		}
		for perm := range role.Permissions {
			result[perm] = struct{}{}
		}
		queue = append(queue, dag.edges[current]...)
	}
	dag.resolved[roleName] = result
	return result
}

// ResolveChildRoles to account for role expiry
func (dag *RoleDAG) ResolveChildRoles(roleName string) map[string]struct{} {
	dag.mu.RLock()
	if roles, found := dag.resolvedRoles[roleName]; found {
		dag.mu.RUnlock()
		return roles
	}
	dag.mu.RUnlock()
	dag.mu.Lock()
	defer dag.mu.Unlock()
	visited := make(map[string]bool)
	queue := []string{roleName}
	result := make(map[string]struct{})
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if visited[current] {
			continue
		}
		visited[current] = true
		role, exists := dag.roles[current]
		if !exists {
			continue
		}
		result[role.Name] = struct{}{}
		queue = append(queue, dag.edges[current]...)
	}
	dag.resolvedRoles[roleName] = result
	return result
}
