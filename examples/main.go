package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/oarflow/cas"
	"github.com/oarflow/cas/utils"
)

func main() {
	authorizer := cas.NewAuthorizer()
	err := LoadPermissions(authorizer)
	if err != nil {
		panic(err)
	}
	request := cas.Request{
		Principal: "21890",
		Tenant:    "1",
	}
	authorized := authorizer.Authorize(request)
	fmt.Println(authorized)
}

func LoadPermissions(auth *cas.Authorizer) error {
	steps := []struct {
		load func(*cas.Authorizer, []map[string]any) error
		name string
	}{
		// {name: "feature-operations.json", load: func(data []map[string]any) error { return LoadAttributes(data) }},
		{name: "role-permissions.json", load: func(auth *cas.Authorizer, data []map[string]any) error { return LoadRoleAttributes(auth, data) }},
		{name: "company-services.json", load: func(auth *cas.Authorizer, data []map[string]any) error { return LoadCompanyServices(auth, data) }},
		{name: "company-entities.json", load: func(auth *cas.Authorizer, data []map[string]any) error { return LoadCompanyEntities(auth, data) }},
		{name: "memberships.json", load: func(auth *cas.Authorizer, data []map[string]any) error { return LoadUserMembership(auth, data) }},
		{name: "user-roles.json", load: func(auth *cas.Authorizer, data []map[string]any) error { return LoadUserMembership(auth, data) }},
	}

	for _, step := range steps {
		var data []map[string]any
		file, err := os.ReadFile(step.name)
		if err != nil {
			return err
		}
		err = json.Unmarshal(file, &data)
		if err != nil {
			return err
		}
		if err = step.load(auth, data); err != nil {
			return err
		}
		data = data[:0]
		clear(data)
	}
	return nil
}

func LoadCompanyServices(auth *cas.Authorizer, data []map[string]any) error {
	for _, item := range data {
		parentCompanyID := utils.ToString(item["parent_company_id"])
		if parentCompanyID != "" {
			_, exists := auth.GetTenant(parentCompanyID)

			if !exists {
				auth.AddTenant(cas.NewTenant(parentCompanyID, parentCompanyID))
			}
		}
	}
	for _, item := range data {
		companyID := utils.ToString(item["company_id"])
		serviceID := utils.ToString(item["service_id"])
		parentCompanyID := utils.ToString(item["parent_company_id"])
		var tenant *cas.Tenant
		if companyID != "" {
			tenant = auth.AddTenant(cas.NewTenant(companyID, companyID))
			if parentCompanyID != "" {
				parent, ok := auth.GetTenant(parentCompanyID)
				if ok {
					parent.AddChildTenant(tenant)
				}
			}
		}
		if serviceID != "" {
			if tenant != nil {
				tenant.AddNamespace(serviceID)
			}
		}
	}
	return nil
}

func LoadCompanyEntities(auth *cas.Authorizer, data []map[string]any) error {
	for _, item := range data {
		companyID := utils.ToString(item["company_id"])
		serviceID := utils.ToString(item["service_id"])
		entityID := utils.ToString(item["entity_id"])
		if companyID != "" && serviceID != "" && entityID != "" {
			tenant, ok := auth.GetTenant(companyID)
			if ok && tenant != nil {
				tenant.AddScopeToNamespace(serviceID, &cas.Scope{ID: entityID})
			}
		}
	}
	return nil
}

func LoadUserMembership(auth *cas.Authorizer, data []map[string]any) error {
	for _, item := range data {
		companyID := utils.ToString(item["company_id"])
		serviceID := utils.ToString(item["service_id"])
		roleID := utils.ToString(item["role_id"])
		entityID := utils.ToString(item["entity_id"])
		userID := utils.ToString(item["user_id"])
		userRole := &cas.PrincipalRole{
			Principal:         userID,
			Tenant:            companyID,
			Scope:             entityID,
			Namespace:         serviceID,
			Role:              roleID,
			ManageChildTenant: true,
		}
		auth.AddPrincipalRole(userRole)
	}
	return nil
}

func LoadRoleAttributes(auth *cas.Authorizer, data []map[string]any) error {
	for _, item := range data {
		roleIDVal := utils.ToString(item["role_id"])
		groupVal := utils.ToString(item["category"])
		attributeVal := utils.ToString(item["route_uri"])
		actionVal := utils.ToString(item["route_method"])
		if roleIDVal != "" {
			role, ok := auth.GetRole(roleIDVal)
			if !ok {
				role = auth.AddRole(cas.NewRole(roleIDVal))
			}
			if groupVal != "" {
				role.AddPermission(&cas.Permission{
					Resource: attributeVal,
					Action:   actionVal,
					Category: groupVal,
				})
			}
		}
	}
	return nil
}

func SimulateAuthorization(authorizer *cas.Authorizer, request cas.Request) {
	fmt.Println("Simulating authorization...")
	authorized := authorizer.Authorize(request)
	fmt.Printf("Simulation result: %v\n", authorized)
}
