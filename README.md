# CAS - Comprehensive Authorization System

CAS is a robust, production-ready permission management library for Go, designed to be more flexible and feature-rich than Casbin. It supports RBAC (Role-Based Access Control), ABAC (Attribute-Based Access Control), multi-tenancy, hierarchical roles, and more.

## Features

- **RBAC with Hierarchies**: Support for role inheritance and complex role graphs.
- **ABAC Hooks**: Extensible attribute-based access control.
- **Multi-Tenancy**: Tenants, namespaces, and scopes for isolated authorization domains.
- **Caching**: LRU caching for performance.
- **Persistence**: Pluggable storage backends (JSON, database, etc.).
- **Policy Management**: Dynamic addition/removal of roles, permissions, and assignments.
- **Validation**: Built-in validation for policy integrity.
- **Metrics**: Authorization metrics for monitoring.
- **Admin Overrides**: Force allow/deny for administrative control.
- **Export/Import**: JSON-based policy serialization.
- **HTTP Middleware**: Ready-to-use middleware for web applications.
- **Wildcard Matching**: Advanced resource pattern matching.

## Installation

```bash
go get github.com/oarkflow/cas
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "github.com/oarkflow/cas"
)

func main() {
    // Create authorizer
    auth := cas.NewAuthorizer()

    // Add roles and permissions
    role := cas.NewRole("admin")
    role.AddPermission(&cas.Permission{Resource: "users/*", Action: "read"})
    auth.AddRole(role)

    // Add tenant
    tenant := cas.NewTenant("company1", "default")
    auth.AddTenant(tenant)

    // Assign role to user
    auth.AddPrincipalRole(&cas.PrincipalRole{
        Principal: "user123",
        Tenant:    "company1",
        Role:      "admin",
    })

    // Authorize request
    req := cas.Request{
        Principal: "user123",
        Tenant:    "company1",
        Resource:  "users/profile",
        Action:    "read",
    }

    if auth.Authorize(context.Background(), req) {
        fmt.Println("Access granted")
    } else {
        fmt.Println("Access denied")
    }
}
```

## Advanced Usage

### ABAC Hooks

```go
auth.RegisterABAC("timeCheck", func(ctx cas.Context) (bool, error) {
    // Custom logic based on attributes
    return true, nil
})
```

### Persistence

```go
// Implement Storage interface
type MyStorage struct{}

func (s *MyStorage) LoadRoles() ([]*cas.Role, error) { /* ... */ }

// Use with authorizer
auth := cas.NewAuthorizer(cas.WithStorage(&MyStorage{}))
auth.LoadEntities()
```

### HTTP Middleware

```go
http.Handle("/api/", auth.Middleware()(http.HandlerFunc(myHandler)))
```

## API Reference

- `NewAuthorizer(opts ...Options) *Authorizer`
- `Authorize(ctx context.Context, req Request) bool`
- `AddRole(role *Role)`
- `AddTenant(tenant *Tenant)`
- `AddPrincipalRole(pr *PrincipalRole)`
- `Validate() error`
- `ExportPolicies() ([]byte, error)`
- `ImportPolicies(data []byte) error`
- `Middleware() func(http.Handler) http.Handler`

## Contributing

Contributions are welcome! Please ensure all tests pass and add tests for new features.

## License

MIT License
