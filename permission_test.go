package rbac

import (
	"testing"
)

func TestPermissions(t *testing.T) {
	// Test that permissions are powers of 2
	permissions := []Permissions{
		CreatePermission, SelfCreatePermission, ReadPermission, SelfReadPermission,
		UpdatePermission, SelfUpdatePermission, DeletePermission, SelfDeletePermission,
	}

	expected := Permissions(1)
	for i, perm := range permissions {
		if perm != expected {
			t.Errorf("Permission %d: expected %d, got %d", i, expected, perm)
		}
		expected <<= 1
	}

	// Test bitwise operations
	combined := CreatePermission | ReadPermission
	if (combined & CreatePermission) != CreatePermission {
		t.Error("Combined permissions should contain CreatePermission")
	}
	if (combined & ReadPermission) != ReadPermission {
		t.Error("Combined permissions should contain ReadPermission")
	}
	if (combined & UpdatePermission) != 0 {
		t.Error("Combined permissions should not contain UpdatePermission")
	}

	// Test permission checking
	required := CreatePermission | ReadPermission
	permitted := CreatePermission | ReadPermission | UpdatePermission

	if (required & permitted) != required {
		t.Error("Permitted should satisfy required")
	}
}
