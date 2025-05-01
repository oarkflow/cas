package cas

import (
	"sync"
)

type Permission struct {
	Resource string
	Action   string
	Category string
}

func NewPermission(category, resource, method string) *Permission {
	return &Permission{Category: category, Resource: resource, Action: method}
}

type Role struct {
	Name        string
	Permissions map[string]struct{}
	m           sync.RWMutex
}

func NewRole(name string) *Role {
	return &Role{Name: name, Permissions: make(map[string]struct{})}
}

type Principal struct {
	ID string
}

func NewPrincipal(name string) *Principal {
	return &Principal{ID: name}
}

type Scope struct {
	ID string
}

func NewScope(name string) *Scope {
	return &Scope{ID: name}
}

type Namespace struct {
	ID     string
	Scopes map[string]*Scope
}

func NewNamespace(name string) *Namespace {
	return &Namespace{ID: name, Scopes: make(map[string]*Scope)}
}

type TenantStatus int

func (t TenantStatus) String() string {
	return [...]string{"active", "inactive", "pending", "blocked", "banned"}[t]
}

const (
	TenantStatusActive TenantStatus = iota
	TenantStatusInactive
	TenantStatusPending
	TenantStatusBlocked
	TenantStatusBanned
)

type Tenant struct {
	ID           string
	Namespaces   map[string]*Namespace
	DefaultNS    string
	Status       TenantStatus
	ChildTenants map[string]*Tenant
	m            sync.RWMutex
}

func NewTenant(id string, defaultNamespace ...string) *Tenant {
	namespaces := make(map[string]*Namespace)
	var defaultNS string
	if len(defaultNamespace) > 0 {
		defaultNS = defaultNamespace[0]
		namespaces[defaultNS] = NewNamespace(defaultNS)
	}
	return &Tenant{
		ID:           id,
		DefaultNS:    defaultNS,
		Namespaces:   namespaces,
		ChildTenants: make(map[string]*Tenant),
	}
}
