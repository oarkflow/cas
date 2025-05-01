package cas

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/oarflow/cas/utils"
)

//

//

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
	Principal string
	Tenant    string
	Namespace string
	Scope     string
	Resource  string
	Action    string
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
			c.order = append(c.order[:i], c.order[i+1:]...)
			c.order = append(c.order, key)
			break
		}
	}
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

type ABACFunc func(request Request, attributes map[string]any) (allow bool, err error)

type Authorizer struct {
	roleDAG            *RoleDAG
	userRoles          []*PrincipalRole
	userRoleMap        map[string]map[string][]*PrincipalRole
	tenants            map[string]*Tenant
	parentCache        map[string]*Tenant
	defaultTenant      string
	auditLog           *slog.Logger
	clock              Clock
	m                  sync.RWMutex
	cacheLock          sync.RWMutex
	abacHooks          []ABACFunc
	permCache          *LRUCache
	roleCache          *LRUCache
	effectiveRoleCache map[cacheKey]map[string]struct{}
	effectivePermCache map[cacheKey]map[string]struct{}
	effectiveCacheLock sync.RWMutex
}

func NewAuthorizer(auditLog ...*slog.Logger) *Authorizer {
	var logger *slog.Logger
	if len(auditLog) > 0 {
		logger = auditLog[0]
	}
	return &Authorizer{
		roleDAG:            NewRoleDAG(),
		tenants:            make(map[string]*Tenant),
		parentCache:        make(map[string]*Tenant),
		userRoleMap:        make(map[string]map[string][]*PrincipalRole),
		auditLog:           logger,
		clock:              RealClock{},
		permCache:          NewLRUCache(1000, 5*time.Minute),
		roleCache:          NewLRUCache(1000, 5*time.Minute),
		effectiveRoleCache: make(map[cacheKey]map[string]struct{}),
		effectivePermCache: make(map[cacheKey]map[string]struct{}),
	}
}

func (a *Authorizer) RegisterABAC(hook ABACFunc) {
	a.abacHooks = append(a.abacHooks, hook)
}

func (a *Authorizer) SetDefaultTenant(tenant string) {
	a.defaultTenant = tenant
}

func (a *Authorizer) updateEffectiveCachesForRole(pr *PrincipalRole) {
	effectiveTenantIDs := []string{pr.Tenant}
	if pr.ManageChildTenant {
		a.m.RLock()
		if tenant, ok := a.tenants[pr.Tenant]; ok {
			effectiveTenantIDs = append(effectiveTenantIDs, tenant.getDescendantIDs()...)
		}
		a.m.RUnlock()
	}
	for _, tid := range effectiveTenantIDs {
		key := cacheKey{
			UserID:    pr.Principal,
			TenantID:  tid,
			Namespace: pr.Namespace,
			Scope:     pr.Scope,
		}
		a.effectiveCacheLock.Lock()
		if a.effectiveRoleCache[key] == nil {
			a.effectiveRoleCache[key] = make(map[string]struct{})
		}
		a.effectiveRoleCache[key][pr.Role] = struct{}{}
		perms := a.roleDAG.ResolvePermissions(pr.Role)
		if a.effectivePermCache[key] == nil {
			a.effectivePermCache[key] = make(map[string]struct{})
		}
		for perm := range perms {
			a.effectivePermCache[key][perm] = struct{}{}
		}
		a.effectiveCacheLock.Unlock()
	}
}

func (a *Authorizer) AddPrincipalRole(userRole ...*PrincipalRole) {
	a.m.Lock()
	defer a.m.Unlock()
	for _, ur := range userRole {
		a.userRoles = append(a.userRoles, ur)
		if a.userRoleMap[ur.Principal] == nil {
			a.userRoleMap[ur.Principal] = make(map[string][]*PrincipalRole)
		}
		a.userRoleMap[ur.Principal][ur.Tenant] = append(a.userRoleMap[ur.Principal][ur.Tenant], ur)
		a.updateEffectiveCachesForRole(ur)
	}
}

func (a *Authorizer) rebuildEffectiveCaches() {
	a.effectiveCacheLock.Lock()
	defer a.effectiveCacheLock.Unlock()
	a.effectiveRoleCache = make(map[cacheKey]map[string]struct{})
	a.effectivePermCache = make(map[cacheKey]map[string]struct{})
	for _, pr := range a.userRoles {
		a.updateEffectiveCachesForRole(pr)
	}
}

func (a *Authorizer) RemovePrincipalRole(target PrincipalRole) error {
	a.m.Lock()
	defer a.m.Unlock()
	rolesRemoved := false
	for i := 0; i < len(a.userRoles); {
		if matches(&target, a.userRoles[i]) {
			rolesRemoved = true
			a.userRoles = append(a.userRoles[:i], a.userRoles[i+1:]...)
		} else {
			i++
		}
	}
	if !rolesRemoved {
		return fmt.Errorf("no matching roles found for the provided criteria")
	}
	for principal, tenants := range a.userRoleMap {
		for tenantID, roles := range tenants {
			for i := 0; i < len(roles); {
				if matches(&target, roles[i]) {
					roles = append(roles[:i], roles[i+1:]...)
				} else {
					i++
				}
			}
			if len(roles) == 0 {
				delete(tenants, tenantID)
			} else {
				a.userRoleMap[principal][tenantID] = roles
			}
		}
		if len(tenants) == 0 {
			delete(a.userRoleMap, principal)
		}
	}
	a.rebuildEffectiveCaches()
	return nil
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

func (a *Authorizer) GetDefaultTenant() (*Tenant, bool) {
	if a.defaultTenant != "" {
		return a.GetTenant(a.defaultTenant)
	}
	return nil, false
}

func (a *Authorizer) ResolvePrincipalPermissions(userID, tenantID, namespace, scopeName string) (map[string]struct{}, error) {
	key := cacheKey{UserID: userID, TenantID: tenantID, Namespace: namespace, Scope: scopeName}
	a.effectiveCacheLock.RLock()
	if perms, found := a.effectivePermCache[key]; found {
		a.effectiveCacheLock.RUnlock()
		return perms, nil
	}
	a.effectiveCacheLock.RUnlock()
	a.cacheLock.RLock()
	if cached, found := a.permCache.Get(key); found {
		a.cacheLock.RUnlock()
		return cached, nil
	}
	a.cacheLock.RUnlock()
	a.m.RLock()
	defer a.m.RUnlock()
	tenant, exists := a.tenants[tenantID]
	if !exists {
		return nil, fmt.Errorf("invalid tenant: %v", tenantID)
	}
	globalPermissions := scopedPermissionsPool.Get()
	scopedPermissions := scopedPermissionsPool.Get()
	defer scopedPermissionsPool.Put(globalPermissions)
	defer scopedPermissionsPool.Put(scopedPermissions)
	var traverse func(current *Tenant) error
	traverse = func(current *Tenant) error {
		for _, userRole := range a.userRoleMap[userID][current.ID] {
			if userRole.IsExpired(a.clock) {
				continue
			}
			if userRole.Namespace == "" || userRole.Namespace == namespace {
				permissions := a.roleDAG.ResolvePermissions(userRole.Role)
				if userRole.Scope == scopeName {
					for perm := range permissions {
						scopedPermissions[perm] = struct{}{}
					}
				} else if userRole.Scope == "" {
					for perm := range permissions {
						globalPermissions[perm] = struct{}{}
					}
				}
			}
		}
		for _, child := range current.ChildTenants {
			if err := traverse(child); err != nil {
				return err
			}
		}
		return nil
	}
	if err := traverse(tenant); err != nil {
		return nil, err
	}
	a.cacheLock.Lock()
	defer a.cacheLock.Unlock()
	if len(scopedPermissions) > 0 {
		a.permCache.Put(key, scopedPermissions)
		return scopedPermissions, nil
	}
	if len(globalPermissions) > 0 {
		a.permCache.Put(key, globalPermissions)
		return globalPermissions, nil
	}
	return nil, fmt.Errorf("no roleDAG or permissions found")
}

func (a *Authorizer) resolvePrincipalRoles(userID, tenantID, namespace string) (map[string]struct{}, error) {
	key := cacheKey{UserID: userID, TenantID: tenantID, Namespace: namespace}
	a.effectiveCacheLock.RLock()
	if roles, found := a.effectiveRoleCache[key]; found {
		a.effectiveCacheLock.RUnlock()
		return roles, nil
	}
	a.effectiveCacheLock.RUnlock()
	a.cacheLock.RLock()
	if cached, found := a.roleCache.Get(key); found {
		a.cacheLock.RUnlock()
		return cached, nil
	}
	a.cacheLock.RUnlock()
	a.m.RLock()
	defer a.m.RUnlock()
	tenant, exists := a.tenants[tenantID]
	if !exists {
		return nil, fmt.Errorf("invalid tenant: %v", tenantID)
	}
	scopedRoles := make(map[string]struct{})
	checkedTenants := make(map[string]bool)
	var traverse func(current *Tenant) error
	traverse = func(current *Tenant) error {
		if checkedTenants[current.ID] {
			return nil
		}
		checkedTenants[current.ID] = true
		for _, userRole := range a.userRoleMap[userID][current.ID] {
			if userRole.IsExpired(a.clock) {
				continue
			}
			if (userRole.Namespace == "" || userRole.Namespace == namespace) && userRole.Role != "" {
				scopedRoles[userRole.Role] = struct{}{}
				for role := range a.roleDAG.ResolveChildRoles(userRole.Role) {
					scopedRoles[role] = struct{}{}
				}
			}
		}
		for _, userRole := range a.userRoleMap[userID][current.ID] {
			if userRole.ManageChildTenant {
				for _, child := range current.ChildTenants {
					if err := traverse(child); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	if err := traverse(tenant); err != nil {
		return nil, err
	}
	a.cacheLock.Lock()
	defer a.cacheLock.Unlock()
	a.roleCache.Put(key, scopedRoles)
	return scopedRoles, nil
}

func (a *Authorizer) FindTargetTenants(request Request) ([]*Tenant, bool) {
	if request.Tenant == "" && a.defaultTenant != "" {
		request.Tenant = a.defaultTenant
	}
	if request.Tenant == "" {
		return a.findPrincipalTenants(request.Principal), true
	}
	var out []*Tenant
	if t, ok := a.tenants[request.Tenant]; ok {
		out = append(out, t)
	}
	if parent, ok := a.parentCache[request.Tenant]; ok {
		if child, exists := parent.ChildTenants[request.Tenant]; exists {
			out = append(out, child, parent)
		}
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

func (a *Authorizer) Log(level slog.Level, request Request, msg string) {
	if a.auditLog != nil {
		args := []any{slog.Time("timestamp", time.Now())}
		if request.Principal != "" {
			args = append(args, slog.String("principal", request.Principal))
		}
		if request.Tenant != "" {
			args = append(args, slog.String("tenant", request.Tenant))
		}
		if request.Namespace != "" {
			args = append(args, slog.String("namespace", request.Namespace))
		}
		if request.Scope != "" {
			args = append(args, slog.String("scope", request.Scope))
		}
		if request.Resource != "" {
			args = append(args, slog.String("resource", request.Resource))
		}
		if request.Action != "" {
			args = append(args, slog.String("action", request.Action))
		}
		a.auditLog.Log(context.Background(), level, msg, args...)
	}
}

func (a *Authorizer) Can(request Request, roles ...string) bool {
	targetTenants, isValidTenant := a.FindTargetTenants(request)
	if !isValidTenant {
		a.Log(slog.LevelWarn, request, "Failed authorization due to invalid tenant")
		return false
	}
	for _, tenant := range targetTenants {
		namespace := request.Namespace
		if namespace == "" {
			if tenant.DefaultNS != "" {
				namespace = tenant.DefaultNS
			} else if len(tenant.Namespaces) == 1 {
				for ns := range tenant.Namespaces {
					namespace = ns
					break
				}
			} else {
				continue
			}
		}
		ns, exists := tenant.Namespaces[namespace]
		if !exists {
			continue
		}
		if request.Scope != "" && !a.isScopeValidForNamespace(ns, request.Scope) {
			continue
		}
		resolvedRoles, err := a.resolvePrincipalRoles(request.Principal, tenant.ID, namespace)
		if err != nil {
			a.Log(slog.LevelWarn, request, "Failed to resolve roles for authorization")
			continue
		}
		for role := range resolvedRoles {
			if slices.Contains(roles, role) {
				a.Log(slog.LevelWarn, request, "Authorization granted")
				return true
			}
		}
	}
	a.Log(slog.LevelWarn, request, "Authorization failed")
	return false
}

func (a *Authorizer) Authorize(request Request) bool {
	targetTenants, isValidTenant := a.FindTargetTenants(request)
	if !isValidTenant {
		a.Log(slog.LevelWarn, request, "Failed authorization due to invalid tenant")
		return false
	}
	for _, tenant := range targetTenants {
		namespace := request.Namespace
		if namespace == "" {
			if tenant.DefaultNS != "" {
				namespace = tenant.DefaultNS
			} else if len(tenant.Namespaces) == 1 {
				for ns := range tenant.Namespaces {
					namespace = ns
					break
				}
			} else {
				continue
			}
		}
		ns, exists := tenant.Namespaces[namespace]
		if !exists {
			continue
		}
		if request.Scope != "" && !a.isScopeValidForNamespace(ns, request.Scope) {
			continue
		}
		key := cacheKey{UserID: request.Principal, TenantID: tenant.ID, Namespace: namespace, Scope: request.Scope}
		a.effectiveCacheLock.RLock()
		perms, found := a.effectivePermCache[key]
		a.effectiveCacheLock.RUnlock()
		if !found {

			var err error
			perms, err = a.ResolvePrincipalPermissions(request.Principal, tenant.ID, namespace, request.Scope)
			if err != nil {
				a.Log(slog.LevelWarn, request, "Failed to resolve permissions for authorization")
				continue
			}
		}

		for perm := range perms {
			if strings.HasPrefix(perm, "DENY:") {
				deniedPattern := strings.TrimPrefix(perm, "DENY:")
				if utils.MatchResource(request.String(), deniedPattern) {
					a.Log(slog.LevelWarn, request, "Authorization denied by explicit DENY")
					return false
				}
			}
		}

		for perm := range perms {
			if strings.HasPrefix(perm, "DENY:") {
				continue
			}
			if utils.MatchResource(request.String(), perm) {
				a.Log(slog.LevelWarn, request, "Authorization granted")
				return true
			}
		}
	}
	a.Log(slog.LevelWarn, request, "Authorization failed")
	return false
}

func (a *Authorizer) isScopeValidForNamespace(ns *Namespace, scopeName string) bool {
	_, exists := ns.Scopes[scopeName]
	return exists
}

func (a *Authorizer) findPrincipalTenants(userID string) []*Tenant {
	tenantSet := make(map[string]*Tenant, len(a.userRoles))
	for _, userRole := range a.userRoles {
		if userRole.Principal == userID && userRole.Tenant != "" {
			if tenant, exists := a.tenants[userRole.Tenant]; exists {
				if tenant.Status == TenantStatusActive {
					tenantSet[userRole.Tenant] = tenant
				}
			}
		}
	}
	tenantList := make([]*Tenant, 0, len(tenantSet))
	for _, tenant := range tenantSet {
		tenantList = append(tenantList, tenant)
	}
	return tenantList
}

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

func (a *Authorizer) AddRolesBulk(roles []*Role) {
	a.roleDAG.AddRole(roles...)
}

func (a *Authorizer) AddPermissionsBulk(roleName string, permissions []*Permission) error {
	role, exists := a.roleDAG.roles[roleName]
	if !exists {
		return fmt.Errorf("role %s does not exist", roleName)
	}
	role.AddPermission(permissions...)
	return nil
}

func (a *Authorizer) invalidateCache() {
	a.cacheLock.Lock()
	defer a.cacheLock.Unlock()
	a.permCache = NewLRUCache(1000, 5*time.Minute)
	a.roleCache = NewLRUCache(1000, 5*time.Minute)
}

func (a *Authorizer) SetCacheTTL(ttl time.Duration) {
	go func() {
		for {
			time.Sleep(ttl)
			a.invalidateCache()
		}
	}()
}

func (a *Authorizer) AuthorizeWithAttributes(request Request, attributes map[string]any) bool {
	for _, hook := range a.abacHooks {
		allow, err := hook(request, attributes)
		if err != nil || !allow {
			return false
		}
	}
	if timeAttr, ok := attributes["time"]; ok {
		if timeAttr.(time.Time).Hour() < 9 || timeAttr.(time.Time).Hour() > 17 {
			return false
		}
	}
	return a.Authorize(request)
}

var (
	metricResolutionCount = 0
	metricCacheHits       = 0
)

func (a *Authorizer) LogMetrics() {
	fmt.Printf("Resolution Count: %d, Cache Hits: %d\n", metricResolutionCount, metricCacheHits)
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

func (a *Authorizer) ListTenants() []*Tenant {
	a.m.RLock()
	defer a.m.RUnlock()
	tenants := make([]*Tenant, 0, len(a.tenants))
	for _, t := range a.tenants {
		tenants = append(tenants, t)
	}
	return tenants
}

func (a *Authorizer) ListRoles() []*Role {
	a.roleDAG.mu.RLock()
	defer a.roleDAG.mu.RUnlock()
	roles := make([]*Role, 0, len(a.roleDAG.roles))
	for _, r := range a.roleDAG.roles {
		roles = append(roles, r)
	}
	return roles
}

func (a *Authorizer) ListAssignments() []*PrincipalRole {
	a.m.RLock()
	defer a.m.RUnlock()
	out := make([]*PrincipalRole, len(a.userRoles))
	copy(out, a.userRoles)
	return out
}

func (a *Authorizer) Clock() Clock {
	return a.clock
}
