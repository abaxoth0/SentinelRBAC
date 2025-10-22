package rbac

import (
	"testing"
)

func TestResource(t *testing.T) {
	// Test resource creation
	resource := NewResource("cache")
	if resource.Name() != "cache" {
		t.Errorf("Expected name 'cache', got %s", resource.Name())
	}

	// Test with empty name
	emptyResource := NewResource("")
	if emptyResource.Name() != "" {
		t.Errorf("Expected empty name, got %s", emptyResource.Name())
	}

	// Test in authorization context
	user := NewEntity("user")
	readAction, _ := user.NewAction("read", ReadPermission)
	ctx := NewAuthorizationContext(&user, readAction, resource)

	if ctx.Resource != resource {
		t.Error("Resource not set correctly in context")
	}
}
