package rbac

import (
	"testing"
)

func TestError(t *testing.T) {
	// Test custom error creation
	err := NewError("test error")
	if err.Error() != "test error" {
		t.Errorf("Expected 'test error', got %s", err.Error())
	}

	// Test error interface implementation
	var errorInterface error = err
	if errorInterface == nil {
		t.Error("Error should implement error interface")
	}

	// Test predefined errors
	if InsufficientPermissions.Error() != "Insufficient permissions to perform this action" {
		t.Error("InsufficientPermissions message incorrect")
	}

	if EntityDoesNotHaveSuchAction.Error() != "Entity doesn't have such action" {
		t.Error("EntityDoesNotHaveSuchAction message incorrect")
	}

	if ActionDeniedByAGP.Error() != "Action has been denied by Action Gate Policy" {
		t.Error("ActionDeniedByAGP message incorrect")
	}

	// Test error comparison
	_ = NewError("same message")
	_ = NewError("same message")
	// Note: Different error instances will never be equal
	// This test documents the current behavior
}
