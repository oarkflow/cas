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

func loadJSON(filename string, out any) error {
	file, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	return json.Unmarshal(file, out)
}
