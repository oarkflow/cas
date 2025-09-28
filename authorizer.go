package cas

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/cas/utils"
)

type Authorizer struct {
	roleDAG            *RoleDAG
	userRoles          []*PrincipalRole
	userRoleMap        map[string]map[string][]*PrincipalRole
	tenants            map[string]*Tenant
	parentCache        map[string]*Tenant
	defaultTenant      string
	auditLog           *slog.Logger
	clock              Clock
	defaultDeny        bool // new flag: if true, non-existing resourceactions default to deny
	tenantsMU          sync.RWMutex
	userRolesMU        sync.RWMutex
	cacheLock          sync.RWMutex
	abacHooks          map[string]ABACFunc
	permCache          *LRUCache
	roleCache          *LRUCache
	effectiveRoleCache map[cacheKey]map[string]struct{}
	effectivePermCache map[cacheKey]map[string]struct{}
	effectiveCacheLock sync.RWMutex
	loaderConfig       LoaderConfig
}

type Options func(*Authorizer)

func WithDefaultDeny(val bool) Options {
	return func(a *Authorizer) {
		a.defaultDeny = val
	}
}

func WithLogger(logger *slog.Logger) Options {
	return func(a *Authorizer) {
		a.auditLog = logger
	}
}

func NewAuthorizer(opts ...Options) *Authorizer {
	auth := &Authorizer{
		roleDAG:            NewRoleDAG(),
		tenants:            make(map[string]*Tenant),
		parentCache:        make(map[string]*Tenant),
		userRoleMap:        make(map[string]map[string][]*PrincipalRole),
		clock:              RealClock{},
		permCache:          NewLRUCache(1000, 5*time.Minute),
		roleCache:          NewLRUCache(1000, 5*time.Minute),
		effectiveRoleCache: make(map[cacheKey]map[string]struct{}),
		effectivePermCache: make(map[cacheKey]map[string]struct{}),
		loaderConfig: LoaderConfig{
			Order: []EntityType{
				EntityRoles, EntityTenants, EntityNamespaces, EntityScopes, EntityPermissions, EntityAssignments,
			},
			Storage: nil,
		},
	}
	for _, opt := range opts {
		opt(auth)
	}
	return auth
}

// LoadEntities loads all entities from the configured storage in the configured order.
func (a *Authorizer) LoadEntities() error {
	if a.loaderConfig.Storage == nil {
		return nil
	}
	for _, entity := range a.loaderConfig.Order {
		switch entity {
		case EntityRoles:
			roles, err := a.loaderConfig.Storage.LoadRoles()
			if err != nil {
				return fmt.Errorf("failed to load roles: %w", err)
			}
			a.AddRoles(roles...)
		case EntityTenants:
			tenants, err := a.loaderConfig.Storage.LoadTenants()
			if err != nil {
				return fmt.Errorf("failed to load tenants: %w", err)
			}
			a.AddTenants(tenants...)
		case EntityNamespaces:
			namespaces, err := a.loaderConfig.Storage.LoadNamespaces()
			if err != nil {
				return fmt.Errorf("failed to load namespaces: %w", err)
			}
			for _, ns := range namespaces {
				if t, ok := a.GetTenant(ns.ID); ok {
					t.AddNamespace(ns.ID)
				}
			}
		case EntityScopes:
			scopes, err := a.loaderConfig.Storage.LoadScopes()
			if err != nil {
				return fmt.Errorf("failed to load scopes: %w", err)
			}
			for _, sc := range scopes {
				for _, t := range a.tenants {
					for ns := range t.Namespaces {
						t.AddScopeToNamespace(ns, sc)
					}
				}
			}
		case EntityPermissions:
			perms, err := a.loaderConfig.Storage.LoadPermissions()
			if err != nil {
				return fmt.Errorf("failed to load permissions: %w", err)
			}
			for _, perm := range perms {
				// Assume Permission.Category is role name
				if role, ok := a.GetRole(perm.Category); ok {
					role.AddPermission(perm)
				}
			}
		case EntityAssignments:
			assignments, err := a.loaderConfig.Storage.LoadAssignments()
			if err != nil {
				return fmt.Errorf("failed to load assignments: %w", err)
			}
			a.AddPrincipalRole(assignments...)
		}
	}
	return nil
}

func (a *Authorizer) updateEffectiveCachesForRole(pr *PrincipalRole) {
	effectiveTenantIDs := []string{pr.Tenant}
	if pr.ManageChildTenant {
		if tenant, ok := a.GetTenant(pr.Tenant); ok {
			effectiveTenantIDs = append(effectiveTenantIDs, tenant.getDescendantIDs()...)
		}
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
	a.userRolesMU.Lock()
	defer a.userRolesMU.Unlock()
	for _, ur := range userRole {
		if ur == nil {
			continue
		}
		a.userRoles = append(a.userRoles, ur)
		if a.userRoleMap[ur.Principal] == nil {
			a.userRoleMap[ur.Principal] = make(map[string][]*PrincipalRole)
		}
		a.userRoleMap[ur.Principal][ur.Tenant] = append(a.userRoleMap[ur.Principal][ur.Tenant], ur)
		a.updateEffectiveCachesForRole(ur)
	}
	a.invalidateCache()
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
	a.userRolesMU.Lock()
	defer a.userRolesMU.Unlock()
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
	a.invalidateCache()
	return nil
}

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
	tenant, exists := a.GetTenant(tenantID)
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
				switch userRole.Scope {
				case scopeName:
					for perm := range permissions {
						scopedPermissions[perm] = struct{}{}
					}
				case "":
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
	tenant, exists := a.GetTenant(tenantID)
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

func (a *Authorizer) AuthorizeContext(ctx context.Context) bool {
	principal, _ := ctx.Value("principal").(string)
	tenant, _ := ctx.Value("tenant").(string)
	namespace, _ := ctx.Value("namespace").(string)
	scope, _ := ctx.Value("scope").(string)
	resource, _ := ctx.Value("resource").(string)
	action, _ := ctx.Value("action").(string)
	attributes, _ := ctx.Value("attributes").(map[string]any)

	req := Request{
		Principal:  principal,
		Tenant:     tenant,
		Namespace:  namespace,
		Scope:      scope,
		Resource:   resource,
		Action:     action,
		Attributes: attributes,
	}
	return a.Authorize(ctx, req)
}

func (a *Authorizer) Authorize(ctx context.Context, request Request) bool {
	ctxx := NewCtx(request, ctx, request.Attributes)
	if len(a.abacHooks) > 0 {
		for _, hook := range a.abacHooks {
			allow, err := hook(ctxx)
			if err != nil || !allow {
				a.Log(slog.LevelWarn, request, "Authorization denied by ABAC hook")
				return false
			}
		}
	}
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
	if a.defaultDeny {
		a.Log(slog.LevelWarn, request, "Authorization failed")
		return false
	}
	a.Log(slog.LevelWarn, request, "Authorization granted by default because ResourceAction doesn't exist")
	return true
}

func (a *Authorizer) RemoveAllTenants() {
	a.tenantsMU.Lock()
	defer a.tenantsMU.Unlock()
	a.tenants = make(map[string]*Tenant)
	a.parentCache = make(map[string]*Tenant)
	a.invalidateCache()
}

func (a *Authorizer) ListTenants() []*Tenant {
	a.tenantsMU.RLock()
	defer a.tenantsMU.RUnlock()
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
	a.userRolesMU.RLock()
	defer a.userRolesMU.RUnlock()
	out := make([]*PrincipalRole, len(a.userRoles))
	copy(out, a.userRoles)
	return out
}

func (a *Authorizer) Clock() Clock {
	return a.clock
}

func (a *Authorizer) invalidateCache() {
	a.cacheLock.Lock()
	defer a.cacheLock.Unlock()
	a.permCache = NewLRUCache(1000, 5*time.Minute)
	a.roleCache = NewLRUCache(1000, 5*time.Minute)
}

func (a *Authorizer) ClearCaches() {
	a.cacheLock.Lock()
	defer a.cacheLock.Unlock()
	a.permCache = NewLRUCache(1000, 5*time.Minute)
	a.roleCache = NewLRUCache(1000, 5*time.Minute)
	a.effectiveCacheLock.Lock()
	defer a.effectiveCacheLock.Unlock()
	a.effectiveRoleCache = make(map[cacheKey]map[string]struct{})
	a.effectivePermCache = make(map[cacheKey]map[string]struct{})
}

func (a *Authorizer) TenantExists(tenantID string) bool {
	a.tenantsMU.RLock()
	defer a.tenantsMU.RUnlock()
	_, exists := a.tenants[tenantID]
	return exists
}

func (a *Authorizer) NamespaceExists(tenantID, namespace string) bool {
	tenant, ok := a.GetTenant(tenantID)
	if !ok {
		return false
	}
	tenant.m.RLock()
	defer tenant.m.RUnlock()
	_, exists := tenant.Namespaces[namespace]
	return exists
}

func (a *Authorizer) ScopeExists(tenantID, namespace, scopeName string) bool {
	tenant, ok := a.GetTenant(tenantID)
	if !ok {
		return false
	}
	tenant.m.RLock()
	defer tenant.m.RUnlock()
	ns, exists := tenant.Namespaces[namespace]
	if !exists {
		return false
	}
	_, exists = ns.Scopes[scopeName]
	return exists
}

func (a *Authorizer) GetDefaultNamespace(tenantID string) (string, error) {
	tenant, ok := a.GetTenant(tenantID)
	if !ok {
		return "", fmt.Errorf("tenant %s does not exist", tenantID)
	}
	tenant.m.RLock()
	defer tenant.m.RUnlock()
	return tenant.DefaultNS, nil
}

func (a *Authorizer) GetDefaultScope(tenantID, namespace string) (string, error) {
	tenant, ok := a.GetTenant(tenantID)
	if !ok {
		return "", fmt.Errorf("tenant %s does not exist", tenantID)
	}
	tenant.m.RLock()
	defer tenant.m.RUnlock()
	ns, exists := tenant.Namespaces[namespace]
	if !exists {
		return "", fmt.Errorf("namespace %s does not exist in tenant %s", namespace, tenantID)
	}
	for scope := range ns.Scopes {
		return scope, nil
	}
	return "", fmt.Errorf("no scopes found in namespace %s of tenant %s", namespace, tenantID)
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
	a.tenantsMU.Lock()
	defer a.tenantsMU.Unlock()
	a.tenants[tenant.ID] = tenant
	a.cacheLock.Lock()
	defer a.cacheLock.Unlock()
	// Recursively update parentCache for all descendants
	var updateParentCache func(parent *Tenant)
	updateParentCache = func(parent *Tenant) {
		for _, child := range parent.ChildTenants {
			a.parentCache[child.ID] = parent
			updateParentCache(child)
		}
	}
	updateParentCache(tenant)
	return tenant
}

func (a *Authorizer) GetTenant(id string) (*Tenant, bool) {
	a.tenantsMU.RLock()
	defer a.tenantsMU.RUnlock()
	tenant, ok := a.tenants[id]
	return tenant, ok
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

func (a *Authorizer) RemoveRole(roleName string) error {
	a.roleDAG.mu.Lock()
	defer a.roleDAG.mu.Unlock()
	if _, exists := a.roleDAG.roles[roleName]; !exists {
		return fmt.Errorf("role %s does not exist", roleName)
	}
	delete(a.roleDAG.roles, roleName)
	delete(a.roleDAG.edges, roleName)
	delete(a.roleDAG.resolved, roleName)
	delete(a.roleDAG.resolvedRoles, roleName)
	a.invalidateCache()
	a.rebuildEffectiveCaches()
	return nil
}

func (a *Authorizer) RemovePermissionFromRole(roleName string, permissions ...*Permission) error {
	a.roleDAG.mu.Lock()
	defer a.roleDAG.mu.Unlock()
	role, exists := a.roleDAG.roles[roleName]
	if !exists {
		return fmt.Errorf("role %s does not exist", roleName)
	}
	role.RemovePermission(permissions...)
	a.invalidateCache()
	a.rebuildEffectiveCaches()
	return nil
}

func (a *Authorizer) ListPermissions(roleName string) ([]string, error) {
	a.roleDAG.mu.RLock()
	defer a.roleDAG.mu.RUnlock()
	role, exists := a.roleDAG.roles[roleName]
	if !exists {
		return nil, fmt.Errorf("role %s does not exist", roleName)
	}
	role.m.RLock()
	defer role.m.RUnlock()
	perms := make([]string, 0, len(role.Permissions))
	for p := range role.Permissions {
		perms = append(perms, p)
	}
	return perms, nil
}

func (a *Authorizer) ListNamespaces(tenantID string) ([]string, error) {
	tenant, ok := a.GetTenant(tenantID)
	if !ok {
		return nil, fmt.Errorf("tenant %s does not exist", tenantID)
	}
	tenant.m.RLock()
	defer tenant.m.RUnlock()
	namespaces := make([]string, 0, len(tenant.Namespaces))
	for ns := range tenant.Namespaces {
		namespaces = append(namespaces, ns)
	}
	return namespaces, nil
}

func (a *Authorizer) ListScopes(tenantID, namespace string) ([]string, error) {
	tenant, ok := a.GetTenant(tenantID)
	if !ok {
		return nil, fmt.Errorf("tenant %s does not exist", tenantID)
	}
	tenant.m.RLock()
	defer tenant.m.RUnlock()
	ns, exists := tenant.Namespaces[namespace]
	if !exists {
		return nil, fmt.Errorf("namespace %s does not exist in tenant %s", namespace, tenantID)
	}
	scopes := make([]string, 0, len(ns.Scopes))
	for s := range ns.Scopes {
		scopes = append(scopes, s)
	}
	return scopes, nil
}

func (a *Authorizer) RoleExists(roleName string) bool {
	a.roleDAG.mu.RLock()
	defer a.roleDAG.mu.RUnlock()
	_, exists := a.roleDAG.roles[roleName]
	return exists
}

func (a *Authorizer) PermissionExists(roleName, perm string) bool {
	a.roleDAG.mu.RLock()
	defer a.roleDAG.mu.RUnlock()
	role, exists := a.roleDAG.roles[roleName]
	if !exists {
		return false
	}
	role.m.RLock()
	defer role.m.RUnlock()
	_, ok := role.Permissions[perm]
	return ok
}

func (a *Authorizer) CleanExpiredPrincipalRoles() {
	a.userRolesMU.Lock()
	defer a.userRolesMU.Unlock()
	now := a.clock.Now()
	filtered := a.userRoles[:0]
	for _, pr := range a.userRoles {
		if pr.Expiry == nil || now.Before(*pr.Expiry) {
			filtered = append(filtered, pr)
		}
	}
	a.userRoles = filtered
	// Clean userRoleMap
	for principal, tenants := range a.userRoleMap {
		for tenantID, roles := range tenants {
			filteredRoles := roles[:0]
			for _, pr := range roles {
				if pr.Expiry == nil || now.Before(*pr.Expiry) {
					filteredRoles = append(filteredRoles, pr)
				}
			}
			if len(filteredRoles) == 0 {
				delete(tenants, tenantID)
			} else {
				a.userRoleMap[principal][tenantID] = filteredRoles
			}
		}
		if len(tenants) == 0 {
			delete(a.userRoleMap, principal)
		}
	}
	a.rebuildEffectiveCaches()
	a.invalidateCache()
}

var (
	metricResolutionCount = 0
	metricCacheHits       = 0
)

func (a *Authorizer) LogMetrics() {
	fmt.Printf("Resolution Count: %d, Cache Hits: %d\n", metricResolutionCount, metricCacheHits)
}

// ABACFunc defines the signature for ABAC hooks.
// It returns (allow, error). If allow is false or error is non-nil, access is denied.
type ABACFunc func(Context) (bool, error)

// RegisterABAC registers an ABAC (attribute-based access control) hook.
// The hook is called before RBAC checks. If any hook returns false or error, access is denied.
func (a *Authorizer) RegisterABAC(name string, hook ABACFunc) {
	if name == "" {
		log.Printf("ABAC hook name cannot be empty")
		return
	}
	if a.abacHooks == nil {
		a.abacHooks = make(map[string]ABACFunc)
	}
	if _, exists := a.abacHooks[name]; exists {
		log.Printf("ABAC hook with name %s already exists, overwriting", name)
	}
	if hook != nil {
		a.abacHooks[name] = hook
	}
}

func (a *Authorizer) RemoveABAC(name string) {
	if a.abacHooks == nil {
		return
	}
	if _, exists := a.abacHooks[name]; exists {
		delete(a.abacHooks, name)
	} else {
		log.Printf("ABAC hook with name %s does not exist", name)
	}
}
