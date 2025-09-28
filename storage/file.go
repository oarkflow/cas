package storage

import (
	"encoding/json"
	"os"
	"time"

	"github.com/oarkflow/cas"
	"github.com/oarkflow/cas/utils"
)

// FileStorage implements cas.Storage interface using JSON files.
type FileStorage struct {
	RoleFile       string
	TenantFile     string
	PermissionFile string
	AssignmentFile string
	NamespaceFile  string
	ScopeFile      string
}

func (fs *FileStorage) LoadRoles() ([]*cas.Role, error) {
	var data []map[string]any
	if err := loadJSON(fs.RoleFile, &data); err != nil {
		return nil, err
	}
	var roles []*cas.Role
	for _, item := range data {
		roleID := utils.ToString(item["role_id"])
		if roleID == "" {
			continue
		}
		role := cas.NewRole(roleID)
		roles = append(roles, role)
	}
	return roles, nil
}

func (fs *FileStorage) LoadTenants() ([]*cas.Tenant, error) {
	var data []map[string]any
	if err := loadJSON(fs.TenantFile, &data); err != nil {
		return nil, err
	}
	var tenants []*cas.Tenant
	for _, item := range data {
		companyID := utils.ToString(item["company_id"])
		if companyID == "" {
			continue
		}
		tenant := cas.NewTenant(companyID, companyID)
		tenants = append(tenants, tenant)
	}
	return tenants, nil
}

func (fs *FileStorage) LoadPermissions() ([]*cas.Permission, error) {
	var data []map[string]any
	if err := loadJSON(fs.PermissionFile, &data); err != nil {
		return nil, err
	}
	var perms []*cas.Permission
	for _, item := range data {
		groupVal := utils.ToString(item["category"])
		attributeVal := utils.ToString(item["route_uri"])
		actionVal := utils.ToString(item["route_method"])
		roleIDVal := utils.ToString(item["role_id"])
		if groupVal != "" && attributeVal != "" && actionVal != "" && roleIDVal != "" {
			perms = append(perms, &cas.Permission{
				Resource: attributeVal,
				Action:   actionVal,
				Category: roleIDVal,
			})
		}
	}
	return perms, nil
}

func (fs *FileStorage) LoadAssignments() ([]*cas.PrincipalRole, error) {
	var data []map[string]any
	if err := loadJSON(fs.AssignmentFile, &data); err != nil {
		return nil, err
	}
	var assignments []*cas.PrincipalRole
	for _, item := range data {
		companyID := utils.ToString(item["company_id"])
		serviceID := utils.ToString(item["service_id"])
		roleID := utils.ToString(item["role_id"])
		entityID := utils.ToString(item["entity_id"])
		userID := utils.ToString(item["user_id"])
		expiryStr := utils.ToString(item["expiry"])
		var expiry *time.Time
		if expiryStr != "" {
			if t, err := time.Parse(time.RFC3339, expiryStr); err == nil {
				expiry = &t
			}
		}
		assignments = append(assignments, &cas.PrincipalRole{
			Principal:         userID,
			Tenant:            companyID,
			Scope:             entityID,
			Namespace:         serviceID,
			Role:              roleID,
			Expiry:            expiry,
			ManageChildTenant: true,
		})
	}
	return assignments, nil
}

func (fs *FileStorage) LoadNamespaces() ([]*cas.Namespace, error) {
	var data []map[string]any
	if err := loadJSON(fs.NamespaceFile, &data); err != nil {
		return nil, err
	}
	var namespaces []*cas.Namespace
	for _, item := range data {
		nsID := utils.ToString(item["service_id"])
		if nsID == "" {
			continue
		}
		namespaces = append(namespaces, cas.NewNamespace(nsID))
	}
	return namespaces, nil
}

func (fs *FileStorage) LoadScopes() ([]*cas.Scope, error) {
	var data []map[string]any
	if err := loadJSON(fs.ScopeFile, &data); err != nil {
		return nil, err
	}
	var scopes []*cas.Scope
	for _, item := range data {
		scopeID := utils.ToString(item["entity_id"])
		if scopeID == "" {
			continue
		}
		scopes = append(scopes, cas.NewScope(scopeID))
	}
	return scopes, nil
}

// SaveRoles saves roles to JSON file
func (fs *FileStorage) SaveRoles(roles []*cas.Role) error {
	var data []map[string]any
	for _, role := range roles {
		data = append(data, map[string]any{"role_id": role.Name})
	}
	return saveJSON(fs.RoleFile, data)
}

// SaveTenants saves tenants to JSON file
func (fs *FileStorage) SaveTenants(tenants []*cas.Tenant) error {
	var data []map[string]any
	for _, tenant := range tenants {
		data = append(data, map[string]any{"company_id": tenant.ID})
	}
	return saveJSON(fs.TenantFile, data)
}

// SavePermissions saves permissions to JSON file
func (fs *FileStorage) SavePermissions(perms []*cas.Permission) error {
	var data []map[string]any
	for _, perm := range perms {
		data = append(data, map[string]any{
			"category":     perm.Category,
			"route_uri":    perm.Resource,
			"route_method": perm.Action,
			"role_id":      perm.Category,
		})
	}
	return saveJSON(fs.PermissionFile, data)
}

// SaveAssignments saves assignments to JSON file
func (fs *FileStorage) SaveAssignments(assignments []*cas.PrincipalRole) error {
	var data []map[string]any
	for _, assign := range assignments {
		item := map[string]any{
			"company_id": assign.Tenant,
			"service_id": assign.Namespace,
			"role_id":    assign.Role,
			"entity_id":  assign.Scope,
			"user_id":    assign.Principal,
		}
		if assign.Expiry != nil {
			item["expiry"] = assign.Expiry.Format(time.RFC3339)
		}
		data = append(data, item)
	}
	return saveJSON(fs.AssignmentFile, data)
}

// SaveNamespaces saves namespaces to JSON file
func (fs *FileStorage) SaveNamespaces(namespaces []*cas.Namespace) error {
	var data []map[string]any
	for _, ns := range namespaces {
		data = append(data, map[string]any{"service_id": ns.ID})
	}
	return saveJSON(fs.NamespaceFile, data)
}

// SaveScopes saves scopes to JSON file
func (fs *FileStorage) SaveScopes(scopes []*cas.Scope) error {
	var data []map[string]any
	for _, scope := range scopes {
		data = append(data, map[string]any{"entity_id": scope.ID})
	}
	return saveJSON(fs.ScopeFile, data)
}

func loadJSON(filename string, out any) error {
	file, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	return json.Unmarshal(file, out)
}

func saveJSON(filename string, data any) error {
	file, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, file, 0644)
}
