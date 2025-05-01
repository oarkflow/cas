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

// Extend Permission to support wildcards
type Permission struct {
	Resource string
	Action   string
	Category string
	Wildcard bool // New field to indicate wildcard support
}

func NewPermission(category, resource, method string, wildcard ...bool) *Permission {
	isWildcard := len(wildcard) > 0 && wildcard[0]
	return &Permission{Category: category, Resource: resource, Action: method, Wildcard: isWildcard}
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
			return err // return the error instead of nil
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
	return p.Resource + " " + p.Action
}

// Extend Request to support dynamic attributes
func (r Request) GetAttribute(key string) (string, bool) {
	switch key {
	case "principal":
		return r.Principal, true
	case "tenant":
		return r.Tenant, true
	case "namespace":
		return r.Namespace, true
	case "scope":
		return r.Scope, true
	case "resource":
		return r.Resource, true
	case "action":
		return r.Action, true
	default:
		return "", false
	}
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

type Authorizer struct {
	roleDAG          *RoleDAG
	userRoles        []*PrincipalRole
	userRoleMap      map[string]map[string][]*PrincipalRole
	tenants          map[string]*Tenant
	parentCache      map[string]*Tenant
	defaultTenant    string
	auditLog         *slog.Logger
	clock            Clock
	m                sync.RWMutex
	permissionsCache map[cacheKey]CacheEntry
	rolesCache       map[cacheKey]map[string]struct{}
	cacheLock        sync.RWMutex
}

func NewAuthorizer(auditLog ...*slog.Logger) *Authorizer {
	var logger *slog.Logger
	if len(auditLog) > 0 {
		logger = auditLog[0]
	}
	return &Authorizer{
		roleDAG:          NewRoleDAG(),
		tenants:          make(map[string]*Tenant),
		parentCache:      make(map[string]*Tenant),
		userRoleMap:      make(map[string]map[string][]*PrincipalRole),
		auditLog:         logger,
		clock:            RealClock{},
		permissionsCache: make(map[cacheKey]CacheEntry),
		rolesCache:       make(map[cacheKey]map[string]struct{}),
	}
}

func (a *Authorizer) SetDefaultTenant(tenant string) {
	a.defaultTenant = tenant
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
	}
}

func (a *Authorizer) RemovePrincipalRole(target PrincipalRole) error {
	a.m.Lock()
	defer a.m.Unlock()
	// Optimize by directly modifying slices and maps
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
	// Update userRoleMap
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
				tenants[tenantID] = roles
			}
		}
		if len(tenants) == 0 {
			delete(a.userRoleMap, principal)
		}
	}
	return nil
}

// Helper function for matching roles
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

// Optimized resolvePrincipalPermissions with caching
func (a *Authorizer) resolvePrincipalPermissions(userID, tenantID, namespace, scopeName string) (map[string]struct{}, error) {
	key := cacheKey{UserID: userID, TenantID: tenantID, Namespace: namespace, Scope: scopeName}

	// Check TTL-based cache
	if cached, found := a.getCachedPermissions(key); found {
		return cached, nil
	}

	// Compute permissions
	a.m.RLock()
	defer a.m.RUnlock()
	tenant, exists := a.tenants[tenantID]
	if !exists {
		return nil, fmt.Errorf("invalid tenant: %v", tenantID)
	}
	globalPermissions := make(map[string]struct{})
	scopedPermissions := make(map[string]struct{})
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

	// Cache the result with TTL
	a.cachePermissions(key, scopedPermissions, 5*time.Minute)
	return scopedPermissions, nil
}

// Optimized resolvePrincipalRoles with caching
func (a *Authorizer) resolvePrincipalRoles(userID, tenantID, namespace string) (map[string]struct{}, error) {
	key := cacheKey{UserID: userID, TenantID: tenantID, Namespace: namespace}

	// Check cache
	a.cacheLock.RLock()
	if cached, found := a.rolesCache[key]; found {
		a.cacheLock.RUnlock()
		return cached, nil
	}
	a.cacheLock.RUnlock()

	// Compute roles
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

	// Cache the result
	a.cacheLock.Lock()
	defer a.cacheLock.Unlock()
	a.rolesCache[key] = scopedRoles
	return scopedRoles, nil
}

// Optimized findTargetTenants to avoid unnecessary slice copy
func (a *Authorizer) findTargetTenants(request Request) ([]*Tenant, bool) {
	if request.Tenant == "" && a.defaultTenant != "" {
		request.Tenant = a.defaultTenant
	}
	if request.Tenant == "" {
		return a.findPrincipalTenants(request.Principal), true
	}
	tenant, exists := a.tenants[request.Tenant]
	if !exists {
		return nil, false
	}
	return []*Tenant{tenant}, true
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
	targetTenants, isValidTenant := a.findTargetTenants(request)
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
	targetTenants, isValidTenant := a.findTargetTenants(request)
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
		permissions, err := a.resolvePrincipalPermissions(request.Principal, tenant.ID, namespace, request.Scope)
		if err != nil {
			a.Log(slog.LevelWarn, request, "Failed to resolve permissions for authorization")
			continue
		}
		for permission := range permissions {
			if matchPermission(permission, request) {
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
	tenantList := make([]*Tenant, len(tenantSet))
	i := 0
	for _, tenant := range tenantSet {
		tenantList[i] = tenant
		i++
	}
	return tenantList
}

// Extend matchPermission to handle wildcards and hierarchical resources
func matchPermission(permission string, request Request) bool {
	if request.Resource == "" && request.Action == "" {
		return false
	}
	requestToCheck := request.String()
	if utils.MatchResource(requestToCheck, permission) {
		return true
	}
	// Handle wildcard matching
	if strings.Contains(permission, "*") {
		return utils.MatchResource(requestToCheck, permission)
	}
	return false
}

// Add support for ABAC (Attribute-Based Access Control)
type ABACPolicy struct {
	Attributes map[string]string // Key-value pairs for dynamic attributes
}

func (a *Authorizer) EvaluateABAC(request Request, policy ABACPolicy) bool {
	for key, value := range policy.Attributes {
		if requestAttr, ok := request.GetAttribute(key); !ok || requestAttr != value {
			return false
		}
	}
	return true
}

// Add support for negative roles
type NegativeRole struct {
	Name        string
	Permissions map[string]struct{}
}

func NewNegativeRole(name string) *NegativeRole {
	return &NegativeRole{Name: name, Permissions: make(map[string]struct{})}
}

func (r *Role) AddNegativePermission(permissions ...*Permission) {
	r.m.Lock()
	defer r.m.Unlock()
	for _, permission := range permissions {
		r.Permissions["-"+permission.String()] = struct{}{}
	}
}

// Add bulk operations for roles and permissions
func (a *Authorizer) AddPrincipalRolesBulk(userRoles []*PrincipalRole) {
	a.m.Lock()
	defer a.m.Unlock()
	for _, ur := range userRoles {
		a.AddPrincipalRole(ur)
	}
}

func (a *Authorizer) RemovePrincipalRolesBulk(targets []PrincipalRole) error {
	a.m.Lock()
	defer a.m.Unlock()
	for _, target := range targets {
		if err := a.RemovePrincipalRole(target); err != nil {
			return err
		}
	}
	return nil
}

// Add event hooks for role/permission changes
type EventHook func(eventType string, data any)

var eventHooks []EventHook

func RegisterEventHook(hook EventHook) {
	eventHooks = append(eventHooks, hook)
}

func triggerEvent(eventType string, data any) {
	for _, hook := range eventHooks {
		hook(eventType, data)
	}
}

// Add TTL-based caching with invalidation
type CacheEntry struct {
	Value      map[string]struct{}
	Expiration time.Time
}

func (a *Authorizer) getCachedPermissions(key cacheKey) (map[string]struct{}, bool) {
	a.cacheLock.RLock()
	defer a.cacheLock.RUnlock()
	entry, found := a.permissionsCache[key]
	if !found || time.Now().After(entry.Expiration) {
		return nil, false
	}
	return entry.Value, true
}

func (a *Authorizer) cachePermissions(key cacheKey, permissions map[string]struct{}, ttl time.Duration) {
	a.cacheLock.Lock()
	defer a.cacheLock.Unlock()
	a.permissionsCache[key] = CacheEntry{
		Value:      permissions,
		Expiration: time.Now().Add(ttl),
	}
}

func (a *Authorizer) invalidateCache(key cacheKey) {
	a.cacheLock.Lock()
	defer a.cacheLock.Unlock()
	delete(a.permissionsCache, key)
}

func (a *Authorizer) AddRoles(role ...*Role) {
	a.roleDAG.AddRole(role...)
}

func (a *Authorizer) AddRole(role *Role) *Role {
	a.AddRoles(role)
	triggerEvent("role_added", role)
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
	return p.Resource + " " + p.Action
}

func (r *Role) AddPermission(permissions ...*Permission) {
	r.m.Lock()
	defer r.m.Unlock()
	for _, permission := range permissions {
		r.Permissions[permission.String()] = struct{}{}
		triggerEvent("permission_added", permission)
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
