package cas

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/oarflow/cas/utils"
)

type PrincipalRole struct {
	Principal         string
	Tenant            string
	Scope             string
	Namespace         string
	Role              string
	Expiry            *time.Time
	ManageChildTenant bool
}

func (pr *PrincipalRole) IsExpired() bool {
	if pr.Expiry == nil {
		return false
	}
	return time.Now().After(*pr.Expiry)
}

func (pr *PrincipalRole) SetExpiry(expiry time.Time) error {
	if expiry.Before(time.Now()) {
		return fmt.Errorf("expiry time has to be in future")
	}
	pr.Expiry = &expiry
	return nil
}

func (pr *PrincipalRole) SetExpiryDuration(dur any) error {
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
	expiry := time.Now().Add(duration)
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

type Authorizer struct {
	roleDAG       *RoleDAG
	userRoles     []*PrincipalRole
	userRoleMap   map[string]map[string][]*PrincipalRole
	tenants       map[string]*Tenant
	parentCache   map[string]*Tenant
	defaultTenant string
	auditLog      *slog.Logger
	m             sync.RWMutex
}

func NewAuthorizer(auditLog ...*slog.Logger) *Authorizer {
	var logger *slog.Logger
	if len(auditLog) > 0 {
		logger = auditLog[0]
	}
	return &Authorizer{
		roleDAG:     NewRoleDAG(),
		tenants:     make(map[string]*Tenant),
		parentCache: make(map[string]*Tenant),
		userRoleMap: make(map[string]map[string][]*PrincipalRole),
		auditLog:    logger,
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
	// rebuild roles without matching role
	var updatedRoles []*PrincipalRole
	var rolesRemoved bool
	matches := func(pr *PrincipalRole) bool {
		if target.Principal != "" && pr.Principal != target.Principal {
			return false
		}
		if target.Tenant != "" && pr.Tenant != target.Tenant {
			return false
		}
		if target.Namespace != "" && pr.Namespace != target.Namespace {
			return false
		}
		if target.Scope != "" && pr.Scope != target.Scope {
			return false
		}
		if target.Role != "" && pr.Role != target.Role {
			return false
		}
		return true
	}
	for _, ur := range a.userRoles {
		if matches(ur) {
			rolesRemoved = true
			continue
		}
		updatedRoles = append(updatedRoles, ur)
	}
	if !rolesRemoved {
		return fmt.Errorf("no matching roles found for the provided criteria")
	}
	a.userRoles = updatedRoles
	// ...existing code to update a.userRoleMap...
	for principal, tenants := range a.userRoleMap {
		for tenantID, roles := range tenants {
			var updatedTenantRoles []*PrincipalRole
			for _, ur := range roles {
				if matches(ur) {
					continue
				}
				updatedTenantRoles = append(updatedTenantRoles, ur)
			}
			if len(updatedTenantRoles) == 0 {
				delete(tenants, tenantID)
			} else {
				tenants[tenantID] = updatedTenantRoles
			}
		}
		if len(tenants) == 0 {
			delete(a.userRoleMap, principal)
		}
	}
	return nil
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

func (a *Authorizer) resolvePrincipalPermissions(userID, tenantID, namespace, scopeName string) (map[string]struct{}, error) {
	tenant, exists := a.tenants[tenantID]
	if !exists {
		return nil, fmt.Errorf("invalid tenant: %v", tenantID)
	}
	globalPermissions := globalPermissionsPool.Get()
	scopedPermissions := scopedPermissionsPool.Get()
	checkedTenants := checkedTenantsPool.Get()
	clear(scopedPermissions)
	clear(globalPermissions)
	clear(checkedTenants)
	defer func() {
		scopedPermissionsPool.Put(scopedPermissions)
		globalPermissionsPool.Put(globalPermissions)
		checkedTenantsPool.Put(checkedTenants)
	}()
	var traverse func(current *Tenant) error
	traverse = func(current *Tenant) error {
		if checkedTenants[current.ID] {
			return nil
		}
		checkedTenants[current.ID] = true
		for _, userRole := range a.userRoles {
			if userRole.Principal != userID || userRole.Tenant != current.ID {
				continue
			}
			if userRole.IsExpired() {
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
		for _, userRole := range a.userRoles {
			if userRole.Principal == userID && userRole.Tenant == current.ID && userRole.ManageChildTenant {
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
	if len(scopedPermissions) > 0 {
		return scopedPermissions, nil
	}
	if len(globalPermissions) > 0 {
		return globalPermissions, nil
	}
	return nil, fmt.Errorf("no roleDAG or permissions found")
}

func (a *Authorizer) resolvePrincipalRoles(userID, tenantID, namespace string) (map[string]struct{}, error) {
	tenant, exists := a.tenants[tenantID]
	if !exists {
		return nil, fmt.Errorf("invalid tenant: %v", tenantID)
	}
	scopedRoles := scopedPermissionsPool.Get()
	checkedTenants := checkedTenantsPool.Get()
	clear(scopedRoles)
	clear(checkedTenants)
	defer func() {
		scopedPermissionsPool.Put(scopedRoles)
		checkedTenantsPool.Put(checkedTenants)
	}()
	var traverse func(current *Tenant) error
	traverse = func(current *Tenant) error {
		if checkedTenants[current.ID] {
			return nil
		}
		checkedTenants[current.ID] = true
		for _, userRole := range a.userRoles {
			if userRole.Principal != userID || userRole.Tenant != current.ID {
				continue
			}
			if userRole.IsExpired() {
				continue
			}
			if (userRole.Namespace == "" || userRole.Namespace == namespace) && userRole.Role != "" {
				scopedRoles[userRole.Role] = struct{}{}
				for role := range a.roleDAG.ResolveChildRoles(userRole.Role) {
					scopedRoles[role] = struct{}{}
				}
			}
		}
		for _, userRole := range a.userRoles {
			if userRole.Principal == userID && userRole.Tenant == current.ID && userRole.ManageChildTenant {
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
	if len(scopedRoles) > 0 {
		return scopedRoles, nil
	}
	return nil, fmt.Errorf("no roleDAG or permissions found")
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

func (a *Authorizer) findTargetTenants(request Request) ([]*Tenant, bool) {
	if request.Tenant == "" && a.defaultTenant != "" {
		request.Tenant = a.defaultTenant
	}
	var tenantBuffer [10]*Tenant
	var targetTenants []*Tenant
	tenantCount := 0
	if request.Tenant == "" {
		tenants := a.findPrincipalTenants(request.Principal)
		tenantCount = len(tenants)
		if tenantCount <= len(tenantBuffer) {
			copy(tenantBuffer[:], tenants)
			targetTenants = tenantBuffer[:tenantCount]
		} else {
			targetTenants = tenants
		}
	} else {
		tenant, exists := a.tenants[request.Tenant]
		if !exists {
			return nil, false
		}
		tenantBuffer[0] = tenant
		tenantCount = 1
		targetTenants = tenantBuffer[:tenantCount]
	}
	return targetTenants, true
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

func matchPermission(permission string, request Request) bool {
	if request.Resource == "" && request.Action == "" {
		return false
	}
	requestToCheck := request.String()
	return utils.MatchResource(requestToCheck, permission)
}
