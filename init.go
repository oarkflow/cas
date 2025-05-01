package cas

func (a *Authorizer) AddRoles(role ...*Role) {
	a.roleDAG.AddRole(role...)
}

func (a *Authorizer) AddRole(role *Role) *Role {
	a.AddRoles(role)
	return role
}

func (a *Authorizer) GetRole(val string) (*Role, bool) {
	role, ok := a.roleDAG.roles[val]
	return role, ok
}

func (a *Authorizer) AddChildRole(parent string, child ...string) error {
	return a.roleDAG.AddChildRole(parent, child...)
}

func (a *Authorizer) AddTenants(tenants ...*Tenant) {
	for _, tenant := range tenants {
		a.AddTenant(tenant)
	}
}

func (a *Authorizer) AddTenant(tenant *Tenant) *Tenant {
	a.m.Lock()
	defer a.m.Unlock()
	a.tenants[tenant.ID] = tenant
	for _, child := range tenant.ChildTenants {
		a.parentCache[child.ID] = tenant
	}
	return tenant
}

func (a *Authorizer) GetTenant(id string) (*Tenant, bool) {
	a.m.RLock()
	defer a.m.RUnlock()
	tenant, ok := a.tenants[id]
	return tenant, ok
}
