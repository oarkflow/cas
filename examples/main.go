package main

import (
	"context"
	"fmt"

	"github.com/oarkflow/cas"
	"github.com/oarkflow/cas/examples/storage"
)

func main() {
	store := &storage.FileStorage{
		RoleFile:       "role-permissions.json",
		TenantFile:     "company-services.json",
		PermissionFile: "role-permissions.json",
		AssignmentFile: "user-roles.json",
		NamespaceFile:  "company-services.json",
		ScopeFile:      "company-entities.json",
	}
	auth := cas.NewAuthorizer(cas.WithStorage(store))
	if err := auth.LoadEntities(); err != nil {
		panic(err)
	}
	auth.RegisterABAC("checkPrincipal", func(ctx cas.Context) (bool, error) {
		attrs := ctx.Attributes()
		req := ctx.Request()
		if len(attrs) == 0 {
			return req.Principal == "21890", nil
		}
		return true, nil
	})
	auth.RegisterABAC("checkBusinessHour", func(ctx cas.Context) (bool, error) {
		attrs := ctx.Attributes()
		if len(attrs) == 0 {
			hour := 10
			return hour >= 9 && hour <= 17, nil
		}
		return true, nil
	})
	auth.RegisterABAC("checkOwner", func(ctx cas.Context) (bool, error) {
		attrs := ctx.Attributes()
		req := ctx.Request()
		if len(attrs) == 0 {
			return true, nil
		}
		return attrs["owner_id"] == req.Principal, nil
	})
	test := func(label string, req cas.Request, expected bool) {
		res := auth.Authorize(context.Background(), req)
		fmt.Printf("%s (should be %v): %v\n", label, expected, res)
	}
	fmt.Println("== ABAC Only (no attributes) ==")
	test("Authorize with correct principal", cas.Request{Principal: "21890", Tenant: "1"}, true)
	test("Authorize with wrong principal", cas.Request{Principal: "99999", Tenant: "1"}, false)
	fmt.Println("\n== ABAC with Attributes ==")
	test("Owner match",
		cas.Request{Principal: "21890", Tenant: "1", Resource: "/resource/123", Action: "read", Attributes: map[string]any{"owner_id": "21890"}},
		true,
	)
	test("Owner mismatch",
		cas.Request{Principal: "21890", Tenant: "1", Resource: "/resource/123", Action: "read", Attributes: map[string]any{"owner_id": "99999"}},
		false,
	)
	test("Reuse valid attribute request",
		cas.Request{Principal: "21890", Tenant: "1", Resource: "/resource/123", Action: "read", Attributes: map[string]any{"owner_id": "21890"}},
		true)
	test("No principal",
		cas.Request{Principal: "", Tenant: "1", Resource: "/resource/123", Action: "read", Attributes: map[string]any{"owner_id": "21890"}},
		false,
	)
}
