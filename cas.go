package cas

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/oarkflow/cas/utils"
)

// Storage interface for loading CAS entities from any source (JSON, CSV, DB, etc.)
type Storage interface {
	LoadRoles() ([]*Role, error)
	LoadTenants() ([]*Tenant, error)
	LoadPermissions() ([]*Permission, error)
	LoadAssignments() ([]*PrincipalRole, error)
	LoadNamespaces() ([]*Namespace, error)
	LoadScopes() ([]*Scope, error)
	SaveRoles([]*Role) error
	SaveTenants([]*Tenant) error
	SavePermissions([]*Permission) error
	SaveAssignments([]*PrincipalRole) error
	SaveNamespaces([]*Namespace) error
	SaveScopes([]*Scope) error
}

// EntityType represents the type of entity to load
type EntityType string

const (
	EntityRoles       EntityType = "roles"
	EntityTenants     EntityType = "tenants"
	EntityPermissions EntityType = "permissions"
	EntityAssignments EntityType = "assignments"
	EntityNamespaces  EntityType = "namespaces"
	EntityScopes      EntityType = "scopes"
)

// LoaderConfig holds the order and types of entities to load
type LoaderConfig struct {
	Order   []EntityType
	Storage Storage
}

// Option to set storage backend
func WithStorage(storage Storage) Options {
	return func(a *Authorizer) {
		a.loaderConfig.Storage = storage
	}
}

// Option to set entity loading order
func WithEntityLoadOrder(order []EntityType) Options {
	return func(a *Authorizer) {
		a.loaderConfig.Order = order
	}
}

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

func (t TenantStatus) Valid() bool {
	return t >= TenantStatusActive && t <= TenantStatusBanned
}

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

func (t *Tenant) Init() {
	if t.Namespaces == nil {
		t.Namespaces = make(map[string]*Namespace)
	}
	if t.ChildTenants == nil {
		t.ChildTenants = make(map[string]*Tenant)
	}
}

func (t *Tenant) getDescendantIDs() []string {
	t.m.RLock()
	defer t.m.RUnlock()
	var ids []string
	for _, child := range t.ChildTenants {
		ids = append(ids, child.ID)
		ids = append(ids, child.getDescendantIDs()...)
	}
	return ids
}

type PrincipalRole struct {
	Principal         string
	Tenant            string
	Scope             string
	Namespace         string
	Role              string
	Expiry            *time.Time
	ManageChildTenant bool
}

func (pr *PrincipalRole) IsExpired(clock Clock) bool {
	if pr.Expiry == nil {
		return false
	}
	return clock.Now().After(*pr.Expiry)
}

func (pr *PrincipalRole) SetExpiry(expiry time.Time, clock Clock) error {
	if expiry.Before(clock.Now()) {
		return fmt.Errorf("expiry time has to be in future")
	}
	pr.Expiry = &expiry
	return nil
}

func (pr *PrincipalRole) SetExpiryDuration(dur any, clock Clock) error {
	var duration time.Duration
	var err error
	switch d := dur.(type) {
	case string:
		duration, err = time.ParseDuration(d)
		if err != nil {
			return err
		}
	case time.Duration:
		duration = d
	default:
		return fmt.Errorf("unsupported duration type")
	}
	expiry := clock.Now().Add(duration)
	pr.Expiry = &expiry
	return nil
}

func (pr *PrincipalRole) ClearExpiry() {
	pr.Expiry = nil
}

type Request struct {
	Principal  string
	Tenant     string
	Namespace  string
	Scope      string
	Resource   string
	Action     string
	Attributes map[string]any
}

func (p Request) String() string {
	return p.Action + " " + p.Resource
}

type Clock interface {
	Now() time.Time
}

type RealClock struct{}

func (RealClock) Now() time.Time {
	return time.Now()
}

type cacheKey struct {
	UserID    string
	TenantID  string
	Namespace string
	Scope     string
}

type LRUCache struct {
	data      map[cacheKey]*CacheEntry
	order     []cacheKey
	capacity  int
	ttl       time.Duration
	cacheLock sync.Mutex
}

type CacheEntry struct {
	Value      map[string]struct{}
	Expiration time.Time
}

func NewLRUCache(capacity int, ttl time.Duration) *LRUCache {
	return &LRUCache{
		data:     make(map[cacheKey]*CacheEntry),
		order:    make([]cacheKey, 0, capacity),
		capacity: capacity,
		ttl:      ttl,
	}
}

func (c *LRUCache) Get(key cacheKey) (map[string]struct{}, bool) {
	c.cacheLock.Lock()
	defer c.cacheLock.Unlock()
	entry, exists := c.data[key]
	if !exists || time.Now().After(entry.Expiration) {
		return nil, false
	}
	c.moveToEnd(key)
	return entry.Value, true
}

func (c *LRUCache) Put(key cacheKey, value map[string]struct{}) {
	c.cacheLock.Lock()
	defer c.cacheLock.Unlock()
	// Remove existing key from order if present
	for i, k := range c.order {
		if k == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
	if len(c.data) >= c.capacity {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.data, oldest)
	}
	c.data[key] = &CacheEntry{Value: value, Expiration: time.Now().Add(c.ttl)}
	c.order = append(c.order, key)
}

func (c *LRUCache) moveToEnd(key cacheKey) {
	for i, k := range c.order {
		if k == key {
			// Remove the key from its current position
			c.order = append(c.order[:i], c.order[i+1:]...)
			break
		}
	}
	c.order = append(c.order, key)
}

type RoleDAG struct {
	mu            sync.RWMutex
	roles         map[string]*Role
	edges         map[string][]string
	resolved      map[string]map[string]struct{}
	resolvedRoles map[string]map[string]struct{}
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

// ValidateRoles checks for circular dependencies in the role DAG.
func (dag *RoleDAG) ValidateRoles() error {
	visited := make(map[string]bool)
	recStack := make(map[string]bool)
	var dfs func(string) error
	dfs = func(role string) error {
		visited[role] = true
		recStack[role] = true
		for _, child := range dag.edges[role] {
			if !visited[child] {
				if err := dfs(child); err != nil {
					return err
				}
			} else if recStack[child] {
				return fmt.Errorf("circular dependency detected involving %s", role)
			}
		}
		recStack[role] = false
		return nil
	}
	for role := range dag.roles {
		if !visited[role] {
			if err := dfs(role); err != nil {
				return err
			}
		}
	}
	return nil
}

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
		for _, child := range dag.edges[current] {
			if !visited[child] {
				queue = append(queue, child)
			}
		}
	}
	dag.resolved[roleName] = result
	return result
}

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
		for _, child := range dag.edges[current] {
			if !visited[child] {
				queue = append(queue, child)
			}
		}
	}
	dag.resolvedRoles[roleName] = result
	return result
}

type Context interface {
	Request() Request
	UserContext() context.Context
	Attributes() map[string]any
}

type Ctx struct {
	request     Request
	userContext context.Context
	attributes  map[string]any
}

func NewCtx(request Request, userContext context.Context, attributes map[string]any) *Ctx {
	return &Ctx{
		request:     request,
		userContext: userContext,
		attributes:  attributes,
	}
}

func (c *Ctx) Request() Request {
	return c.request
}

func (c *Ctx) UserContext() context.Context {
	return c.userContext
}

func (c *Ctx) Attributes() map[string]any {
	if c.attributes == nil {
		return make(map[string]any)
	}
	return c.attributes
}

func matches(target, role *PrincipalRole) bool {
	if target.Principal != "" && target.Principal != role.Principal {
		return false
	}
	if target.Tenant != "" && target.Tenant != role.Tenant {
		return false
	}
	if target.Namespace != "" && target.Namespace != role.Namespace {
		return false
	}
	if target.Scope != "" && target.Scope != role.Scope {
		return false
	}
	if target.Role != "" && target.Role != role.Role {
		return false
	}
	return true
}

var (
	scopedPermissionsPool = utils.New(func() map[string]struct{} { return make(map[string]struct{}) })
	globalPermissionsPool = utils.New(func() map[string]struct{} { return make(map[string]struct{}) })
	checkedTenantsPool    = utils.New(func() map[string]bool { return make(map[string]bool) })
)

func (p *Permission) String() string {
	return p.Action + " " + p.Resource
}

func (r *Role) AddPermission(permissions ...*Permission) {
	r.m.Lock()
	defer r.m.Unlock()
	for _, permission := range permissions {
		r.Permissions[permission.String()] = struct{}{}
	}
}

func (r *Role) AddDenyPermission(permissions ...*Permission) {
	r.m.Lock()
	defer r.m.Unlock()
	for _, permission := range permissions {
		r.Permissions["DENY:"+permission.String()] = struct{}{}
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

func (t *Tenant) AddChildTenantWithInheritance(tenant *Tenant, inheritRoles bool) {
	t.m.Lock()
	defer t.m.Unlock()
	t.ChildTenants[tenant.ID] = tenant
	if inheritRoles {
		for nsID, ns := range t.Namespaces {
			if _, exists := tenant.Namespaces[nsID]; !exists {
				tenant.Namespaces[nsID] = NewNamespace(nsID)
			}
			for scopeID, scope := range ns.Scopes {
				tenant.Namespaces[nsID].Scopes[scopeID] = scope
			}
		}
		for _, role := range t.ChildTenants {
			for _, childRole := range role.ChildTenants {
				tenant.ChildTenants[childRole.ID] = childRole
			}
		}
	}
}
