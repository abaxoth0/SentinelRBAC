package rbac

import (
	"testing"
)

func TestRole(t *testing.T) {
	// Test role creation
	role := NewRole("admin", CreatePermission|ReadPermission)

	if role.Name != "admin" {
		t.Errorf("Expected name 'admin', got %s", role.Name)
	}

	if role.Permissions != (CreatePermission | ReadPermission) {
		t.Errorf("Expected combined permissions, got %d", role.Permissions)
	}

	// Test GetRolesNames
	roles := []Role{
		NewRole("admin", CreatePermission),
		NewRole("user", ReadPermission),
	}

	names := GetRolesNames(roles)
	expected := []string{"admin", "user"}

	if len(names) != len(expected) {
		t.Errorf("Expected %d names, got %d", len(expected), len(names))
	}

	for i, name := range names {
		if name != expected[i] {
			t.Errorf("Expected name %s, got %s", expected[i], name)
		}
	}
}
