package main

import (
	"fmt"
	"net/http"

	"github.com/oarkflow/cas"
)

func main() {
	fmt.Println("=== HTTP Middleware Example ===")

	auth := cas.NewAuthorizer()

	// Setup basic data
	adminRole := cas.NewRole("admin")
	adminRole.AddPermission(&cas.Permission{Resource: "api/admin/*", Action: "GET"})
	auth.AddRole(adminRole)

	userRole := cas.NewRole("user")
	userRole.AddPermission(&cas.Permission{Resource: "api/user/*", Action: "GET"})
	auth.AddRole(userRole)

	tenant := cas.NewTenant("company1", "default")
	auth.AddTenant(tenant)

	auth.AddPrincipalRole(&cas.PrincipalRole{
		Principal: "alice",
		Tenant:    "company1",
		Role:      "admin",
	})
	auth.AddPrincipalRole(&cas.PrincipalRole{
		Principal: "bob",
		Tenant:    "company1",
		Role:      "user",
	})

	// Create middleware
	middleware := auth.Middleware()

	// Create test handler
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Access granted to %s", r.URL.Path)
	}))

	// Simulate requests
	testRequests := []struct {
		method   string
		url      string
		headers  map[string]string
		expected int
	}{
		{"GET", "/api/admin/dashboard", map[string]string{"X-Principal": "alice", "X-Tenant": "company1"}, 200},
		{"GET", "/api/admin/dashboard", map[string]string{"X-Principal": "bob", "X-Tenant": "company1"}, 403},
		{"GET", "/api/user/profile", map[string]string{"X-Principal": "bob", "X-Tenant": "company1"}, 200},
		{"GET", "/api/user/profile", map[string]string{"X-Principal": "charlie", "X-Tenant": "company1"}, 403},
	}

	for i, test := range testRequests {
		req, _ := http.NewRequest(test.method, test.url, nil)
		for k, v := range test.headers {
			req.Header.Set(k, v)
		}

		w := &responseRecorder{}
		handler.ServeHTTP(w, req)

		status := "✓"
		if w.status != test.expected {
			status = "✗"
		}
		fmt.Printf("%s Request %d: %s %s -> %d (expected %d)\n", status, i+1, test.method, test.url, w.status, test.expected)
	}

	fmt.Println("HTTP Middleware example completed.")
}

// responseRecorder captures HTTP response
type responseRecorder struct {
	status int
	body   []byte
}

func (r *responseRecorder) Header() http.Header {
	return make(http.Header)
}

func (r *responseRecorder) Write(data []byte) (int, error) {
	r.body = append(r.body, data...)
	return len(data), nil
}

func (r *responseRecorder) WriteHeader(status int) {
	r.status = status
}
