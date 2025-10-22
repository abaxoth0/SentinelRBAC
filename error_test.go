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
	err1 := NewError("same message")
	err2 := NewError("same message")
	if err1 == err2 {
		t.Error("Different error instances should not be equal")
	}
}
