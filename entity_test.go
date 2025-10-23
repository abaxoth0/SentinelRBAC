package rbac

import (
	"testing"
)

func TestEntity(t *testing.T) {
	entity := NewEntity("user")

	// Test basic functionality
	if entity.Name() != "user" {
		t.Errorf("Expected name 'user', got %s", entity.Name())
	}

	// Test action creation
	readAction, err := entity.NewAction("read", ReadPermission)
	if err != nil {
		t.Fatalf("Failed to create action: %v", err)
	}

	if !entity.HasAction(readAction) {
		t.Error("Entity should have read action")
	}

	// Test duplicate action
	_, err = entity.NewAction("read", CreatePermission)
	if err == nil {
		t.Error("Expected error for duplicate action")
	}

	// Test getting permissions
	perms, exists := entity.GetRequiredActionPermissions(readAction)
	if !exists {
		t.Error("Should be able to get permissions")
	}
	if perms != ReadPermission {
		t.Errorf("Expected ReadPermission, got %d", perms)
	}

	// Test action removal
	entity.RemoveAction(readAction)
	if entity.HasAction(readAction) {
		t.Error("Action should be removed")
	}
}
