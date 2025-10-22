package rbac

import (
	"testing"
)

func TestAuthorizationContext(t *testing.T) {
	user := NewEntity("user")
	readAction, _ := user.NewAction("read", ReadPermission)
	cache := NewResource("cache")

	ctx := NewAuthorizationContext(&user, readAction, cache)

	// Test basic properties
	if ctx.Entity != &user {
		t.Error("Entity not set correctly")
	}
	if ctx.Action != readAction {
		t.Error("Action not set correctly")
	}
	if ctx.Resource != cache {
		t.Error("Resource not set correctly")
	}

	// Test string representation
	expected := "user:read:cache"
	if ctx.String() != expected {
		t.Errorf("Expected %s, got %s", expected, ctx.String())
	}
}
