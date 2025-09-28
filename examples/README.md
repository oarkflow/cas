# CAS Examples

This directory contains comprehensive examples demonstrating all features of the CAS (Comprehensive Authorization System) library.

## Examples Overview

### 1. Basic RBAC (`basic_rbac/`)
Demonstrates fundamental Role-Based Access Control setup:
- Creating roles and permissions
- Setting up tenants
- Assigning roles to users
- Basic authorization checks

```bash
cd examples/basic_rbac
go run main.go
```

### 2. Role Hierarchy (`role_hierarchy/`)
Shows how to create hierarchical role relationships:
- Parent-child role inheritance
- Permission inheritance through role chains
- Complex authorization scenarios

```bash
cd examples/role_hierarchy
go run main.go
```

### 3. Multi-Tenancy (`multi_tenancy/`)
Illustrates multi-tenant authorization:
- Multiple tenants with isolated data
- Namespaces and scopes within tenants
- Hierarchical tenant relationships
- Cross-tenant permission isolation

```bash
cd examples/multi_tenancy
go run main.go
```

### 4. Persistence (`persistence/`)
Demonstrates saving and loading policies:
- File-based storage implementation
- Saving policy changes
- Loading policies into new authorizer instances

```bash
cd examples/persistence
go run main.go
```

### 5. ABAC (Attribute-Based Access Control) (`abac/`)
Shows attribute-based authorization:
- Custom ABAC hooks
- Context-aware decision making
- Business logic integration

```bash
cd examples/abac
go run main.go
```

### 6. Validation (`validation/`)
Demonstrates policy validation:
- Detecting circular role dependencies
- Validating tenant and role configurations
- Error handling for invalid setups

```bash
cd examples/validation
go run main.go
```

### 7. Export/Import (`export_import/`)
Shows policy serialization:
- Exporting policies to JSON
- Importing policies from JSON
- Backup and migration scenarios

```bash
cd examples/export_import
go run main.go
```

### 8. Metrics (`metrics/`)
Illustrates monitoring capabilities:
- Authorization metrics collection
- Performance statistics
- Usage analytics

```bash
cd examples/metrics
go run main.go
```

### 9. Admin Overrides (`admin_overrides/`)
Demonstrates administrative controls:
- Force allow/deny decisions
- Emergency access management
- Override capabilities

```bash
cd examples/admin_overrides
go run main.go
```

### 10. HTTP Middleware (`middleware/`)
Shows web integration:
- HTTP middleware for automatic authorization
- Header-based context extraction
- Web application integration

```bash
cd examples/middleware
go run main.go
```

### 11. Advanced Permissions (`advanced_permissions/`)
Covers advanced permission features:
- Wildcard and parameter matching
- Explicit deny permissions
- Role expiry and cleanup
- Complex permission patterns

```bash
cd examples/advanced_permissions
go run main.go
```

## Running All Examples

To run all examples in sequence:

```bash
for dir in */; do
    if [ -f "$dir/main.go" ]; then
        echo "Running $dir"
        cd "$dir"
        go run main.go
        cd ..
        echo
    fi
done
```

## Storage Implementation

The `storage/file.go` file provides a complete file-based storage implementation that supports all CAS storage interfaces including the new Save methods.

## JSON Data Files

The examples use various JSON files for demonstration:
- `company-entities.json` - Scope/entity definitions
- `company-roles.json` - Role data
- `company-services.json` - Namespace/service data
- `user-roles.json` - User role assignments
- `role-permissions.json` - Permission mappings

These files contain sample data for testing the persistence and loading features.
